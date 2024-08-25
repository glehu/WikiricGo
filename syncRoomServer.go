package main

import (
	"context"
	"encoding/json"
	"firebase.google.com/go/messaging"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/tidwall/btree"
	"net/http"
	"nhooyr.io/websocket"
	"sync"
	"sync/atomic"
	"time"
)

type SyncedSession struct {
	User     *User
	Conn     *websocket.Conn
	Ctx      context.Context
	R        *http.Request
	RoomId   string
	RoomName string
}

type SyncCacheEntry struct {
	LastCheck time.Time
	Usernames []string
}

type SyncRoomServer struct {
	SyncRoomsMu *sync.RWMutex
	// Map of ChatGroupUUID as key and map of ChatMemberUsername and Session as value
	SyncRooms *btree.Map[string, map[string]*SyncedSession]
	tokenAuth *jwtauth.JWTAuth
	// ChatMessageDB
	DB                  *GoDB
	MainDB              *GoDB
	NotificationCounter *atomic.Int64
	Connector           *Connector
}

type SyncMessageContainer struct {
	*SyncMessage
	UUID string
}

type SyncMessageResponse struct {
	Typ websocket.MessageType
	Msg []byte
}

type SyncMessage struct {
	RoomId      string
	Text        string
	Username    string
	TimeCreated string
}

func CreateSyncRoomServer(db, mainDB *GoDB, connector *Connector) *SyncRoomServer {
	server := &SyncRoomServer{
		SyncRoomsMu:         &sync.RWMutex{},
		SyncRooms:           btree.NewMap[string, map[string]*SyncedSession](3),
		DB:                  db,
		MainDB:              mainDB,
		NotificationCounter: &atomic.Int64{},
		Connector:           connector,
	}
	return server
}

// PublicSyncRoomEndpoint will manage all websocket connections
func (server *SyncRoomServer) PublicSyncRoomEndpoint(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
	dbList *Databases,
	connector *Connector, fcmClient *messaging.Client,
) {
	server.tokenAuth = tokenAuth
	// Route
	r.HandleFunc(
		"/ws/synced/{roomID}",
		server.handleSyncedEndpoint(
			dbList.Map["main"], dbList.Map["rapid"],
			connector, fcmClient,
		),
	)
}

func (server *SyncRoomServer) handleSyncedEndpoint(
	mainDB, rapidDB *GoDB,
	connector *Connector, fcmClient *messaging.Client,
) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		roomID := chi.URLParam(r, "roomID")
		if roomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Accept websocket connection to check token
		c, err := websocket.Accept(
			w,
			r,
			&websocket.AcceptOptions{InsecureSkipVerify: true}, // DEBUG
		)
		if err != nil {
			return
		}
		validToken, _, r := server.checkToken(mainDB, c, r)
		if !validToken {
			_ = c.Close(
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			)
			return
		}
		ctx := r.Context()
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Say hi! Send write and read rights over the websocket connection
		str := fmt.Sprint("[s:wlcm]")
		err = c.Write(
			ctx,
			1, // 1=Text
			[]byte(str),
		)
		if err != nil {
			return
		}
		server.SyncRoomsMu.Lock()
		sessions, ok := server.SyncRooms.Get(roomID)
		session := &SyncedSession{
			User:   user,
			Conn:   c,
			Ctx:    ctx,
			R:      r,
			RoomId: roomID,
		}
		if ok {
			sessions[user.Username] = session
			server.SyncRooms.Set(roomID, sessions)
		} else {
			server.SyncRooms.Set(
				roomID,
				map[string]*SyncedSession{
					user.Username: session,
				},
			)
		}
		server.SyncRoomsMu.Unlock()
		server.handleSyncedSession(session, mainDB, rapidDB, fcmClient)
	}
}

func (server *SyncRoomServer) checkToken(
	mainDB *GoDB,
	c *websocket.Conn,
	r *http.Request,
) (bool, jwt.Token, *http.Request) {
	// Listen for message
	ctx := r.Context()
	_, msg, err := c.Read(ctx)
	if err != nil {
		return false, nil, nil
	}
	// Check JWT Token
	token, err := server.tokenAuth.Decode(string(msg))
	if err != nil {
		return false, nil, nil
	}
	// Check token's expiry date
	expTmp, ok := token.Get("exp")
	if ok != true {
		return false, nil, nil
	}
	exp := expTmp.(time.Time)
	expired := exp.Compare(time.Now()) < 0
	if expired {
		return false, nil, nil
	}
	// Does the user exist?
	userName, _ := token.Get("u_name")
	// Get client user (we need to fmt because userName is an interface, not a string)
	userQuery := FIndex(fmt.Sprintf("%s", userName))
	resp, err := mainDB.Select(UserDB,
		map[string]string{
			"usr": userQuery,
		}, nil,
	)
	if err != nil {
		return false, nil, nil
	}
	response := <-resp
	if len(response) < 1 {
		return false, nil, nil
	}
	userFromDB := &User{}
	err = json.Unmarshal(response[0].Data, userFromDB)
	if err != nil {
		fmt.Println(err)
		return false, nil, nil
	}
	// Set user to context to be used for next steps after this middleware
	r = r.WithContext(context.WithValue(ctx, "user", userFromDB))
	r = r.WithContext(context.WithValue(r.Context(), "userID", response[0].uUID))
	return true, token, r
}

func (server *SyncRoomServer) handleSyncedSession(s *SyncedSession,
	mainDB, rapidDB *GoDB, fcmClient *messaging.Client,
) {
	messages, closed := ListenToSyncedMessages(
		s.Conn,
		s.Ctx,
	)
	for {
		select {
		case <-closed:
			server.dropConnection(s)
			return
		case <-s.Ctx.Done():
			server.dropConnection(s)
			return
		case resp := <-messages:
			if resp != nil {
				server.handleIncomingMessage(
					s,
					resp,
					mainDB, rapidDB, fcmClient,
				)
			}
		}
	}
}

func (server *SyncRoomServer) dropConnection(s *SyncedSession) {
	server.SyncRoomsMu.Lock()
	defer server.SyncRoomsMu.Unlock()
	sessions, ok := server.SyncRooms.Get(s.RoomId)
	if ok {
		delete(sessions, s.User.Username)
		// Are there any connections left? If not, then delete the chat session
		if len(sessions) < 1 {
			server.SyncRooms.Delete(s.RoomId)
		} else {
			server.SyncRooms.Set(s.RoomId, sessions)
		}
	}
}

func (server *SyncRoomServer) handleIncomingMessage(
	s *SyncedSession,
	resp *SyncMessageResponse,
	mainDB, rapidDB *GoDB,
	fcmClient *messaging.Client,
) {
	text := string(resp.Msg)
	msg := &SyncMessage{
		RoomId:      s.RoomId,
		Text:        text,
		Username:    s.User.Username,
		TimeCreated: TimeNowIsoString(),
	}
	uUID := ""
	if len(text) >= 5 && text[0:5] == "[c:S]" {
		jsonEntry, err := json.Marshal(msg)
		if err != nil {
			return
		}
		uUID, _ = server.DB.Insert(MessageDB, jsonEntry, map[string]string{
			"roomID": s.RoomId,
		})
	}
	go server.DistributeSyncedMessageJSON(&SyncMessageContainer{
		SyncMessage: msg,
		UUID:        uUID,
	})
}

func (server *SyncRoomServer) DistributeSyncedMessageJSON(msg *SyncMessageContainer) {
	// Distribute chat message to all members of this channel
	server.SyncRoomsMu.RLock()
	sessions, ok := server.SyncRooms.Get(msg.RoomId)
	server.SyncRoomsMu.RUnlock()
	if !ok {
		return
	}
	for _, value := range sessions {
		if value.User.Username == msg.Username {
			// Do not distribute a message to the sender itself
			continue
		}
		_ = WSSendJSON(value.Conn, value.Ctx, msg) // TODO: Drop connection?
	}
}

func ListenToSyncedMessages(
	c *websocket.Conn,
	ctx context.Context,
) (chan *SyncMessageResponse, chan bool) {
	// Prepare channels
	resp := make(chan *SyncMessageResponse)
	closed := make(chan bool)
	// Launch goroutine with listening loop
	go func() {
		for {
			typ, msg, err := c.Read(ctx)
			if err != nil {
				closed <- true
				return
			}
			resp <- &SyncMessageResponse{
				Typ: typ,
				Msg: msg,
			}
		}
	}()
	return resp, closed
}
