package main

import (
	"bytes"
	"context"
	"encoding/json"
	"firebase.google.com/go/messaging"
	"fmt"
	"github.com/coder/websocket"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/pion/webrtc/v4"
	"github.com/tidwall/btree"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type SyncedSession struct {
	Mu     *sync.RWMutex
	User   *User
	Conn   *websocket.Conn
	Ctx    context.Context
	R      *http.Request
	RoomId string
	Room   *SyncRoom
	// PPState 0 = Pong1 else 1 = Pong2
	PPState   int
	Ping1Time time.Time
	Pong1Time time.Time
	Ping2Time time.Time
	Pong2Time time.Time
	LatencyMS float32
	// WebRTC Connection
	PeerCon *webrtc.PeerConnection
	// WebRTC DataChannel
	PeerData *webrtc.DataChannel
}

type SyncedSessionSum struct {
	Username  string  `json:"u"`
	LatencyMS float32 `json:"l"`
	IsOwner   bool    `json:"o"`
}

type SyncedSessionDataSum struct {
	Username string `json:"u"`
	Key      string `json:"k"`
	Value    string `json:"v"`
}

type SyncRoom struct {
	Mu        *sync.RWMutex
	Sessions  map[string]*SyncedSession
	Name      string
	RoomOwner string
	// Data is a key value map for arbitrary string data (most likely JSON)
	Data map[string]string
	// DataOwners keeps track of all data keys mapped to their owner
	DataOwners map[string][]string
	Timer      *time.Ticker
}

type SyncRoomContainer struct {
	Room *SyncRoom
}

type SyncRoomServer struct {
	SyncRoomsMu *sync.RWMutex
	// Map of RoomID as key and SyncRoom as value, containing the SyncedSession instances
	SyncRooms           *btree.Map[string, SyncRoomContainer]
	tokenAuth           *jwtauth.JWTAuth
	DB                  *GoDB
	MainDB              *GoDB
	NotificationCounter *atomic.Int64
	Connector           *Connector
}

type SyncMessageContainer struct {
	*SyncMessage
}

type SyncMessageResponse struct {
	Typ websocket.MessageType
	Msg []byte
}

type SyncMessage struct {
	Text        string `json:"t,omitempty"`
	Username    string `json:"u,omitempty"`
	Action      string `json:"a,omitempty"`
	TimeCreated string `json:"c,omitempty"` // Chronos ;)
}

func CreateSyncRoomServer(db, mainDB *GoDB, connector *Connector) *SyncRoomServer {
	server := &SyncRoomServer{
		SyncRoomsMu:         &sync.RWMutex{},
		SyncRooms:           btree.NewMap[string, SyncRoomContainer](3),
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
		server.SyncRoomsMu.Lock()
		room, ok := server.SyncRooms.Get(roomID)
		session := &SyncedSession{
			Mu:     &sync.RWMutex{},
			User:   user,
			Conn:   c,
			Ctx:    ctx,
			R:      r,
			RoomId: roomID,
			Room:   room.Room,
		}
		var rName string
		if ok {
			// Add to room's session
			room.Room.Mu.Lock()
			room.Room.Sessions[user.Username] = session
			room.Room.Mu.Unlock()
			server.SyncRooms.Set(roomID, room)
			rName = room.Room.Name
		} else {
			// Create room and session
			rName = fmt.Sprintf("Room %s", roomID)
			server.SyncRooms.Set(
				roomID,
				SyncRoomContainer{
					&SyncRoom{
						Mu: &sync.RWMutex{},
						Sessions: map[string]*SyncedSession{
							user.Username: session,
						},
						Name:       rName,
						RoomOwner:  user.Username,
						Data:       make(map[string]string),
						DataOwners: make(map[string][]string),
						Timer:      nil,
					},
				},
			)
		}
		// Say hi! Send write and read rights over the websocket connection
		str := fmt.Sprintf("[s:wlcm]%s", rName)
		err = c.Write(
			ctx,
			1, // 1=Text
			[]byte(str),
		)
		if err != nil {
			return
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
	room, ok := server.SyncRooms.Get(s.RoomId)
	if ok {
		room.Room.Mu.Lock()
		delete(room.Room.Sessions, s.User.Username)
		// Are there any connections left? If not, then delete the chat session
		if len(room.Room.Sessions) < 1 {
			room.Room.Mu.Unlock()
			server.SyncRooms.Delete(s.RoomId)
		} else {
			room.Room.Mu.Unlock()
			server.SyncRooms.Set(s.RoomId, room)
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
	var act = ""
	var targetSession *SyncedSession = nil
	var exit = false
	// Check for pre-defined commands
	// If the message does not match with anything, it still gets distributed
	if CheckPrefix(text, "[c:B]") {
		// B stands for Pong, the response to a Ping (or A)
		act, targetSession = handlePongResponse(s)
	} else if CheckPrefix(text, "[c:L]") {
		// L stands for Latency Check
		s.PPState = 0
		targetSession = s
		act = "[s:A]"
	} else if CheckPrefix(text, "[c:SET;NAME]") {
		act, targetSession = handleSetRoomName(server, s, text)
	} else if CheckPrefix(text, "[c:SET;DATA]") {
		act, targetSession = handleSetRoomData(server, s, text)
	} else if CheckPrefix(text, "[c:GET;DATA]") {
		act, targetSession = handleGetRoomData(server, s, text)
	} else if CheckPrefix(text, "[c:GET;SESH]") {
		act, targetSession, exit = handleGetRoomSessions(server, s, text)
	} else if CheckPrefix(text, "[c:GET;UDAT]") {
		act, targetSession, exit = handleGetRoomSessionData(server, s, text)
	} else if CheckPrefix(text, "[c:DC]") {
		act, targetSession = handleDisconnectUser(server, s, text)
	} else if CheckPrefix(text, "[c:WRTC]") {
		HandleWebRTCRequest(server, s, text)
		exit = true
	}
	if exit {
		return
	}
	msg := &SyncMessage{
		Text:     text,
		Username: s.User.Username,
		Action:   act,
	}
	go server.DistributeSyncedMessageJSON(s.RoomId, &SyncMessageContainer{SyncMessage: msg}, targetSession)
	if CheckPrefix(text, "[c:S]") {
		jsonEntry, err := json.Marshal(msg)
		if err != nil {
			return
		}
		_, _ = server.DB.Insert(MessageDB, jsonEntry, map[string]string{
			"roomID": s.RoomId,
		})
	}
}

func (server *SyncRoomServer) DistributeSyncedMessageJSON(roomId string, msg *SyncMessageContainer, targetSession *SyncedSession) {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(msg); err != nil {
		return
	}
	if targetSession != nil {
		// Is this a Ping? If so, remember this moment's times
		if msg.Action == "[s:A]" {
			if targetSession.PPState == 0 {
				targetSession.Ping1Time = time.Now()
			} else if targetSession.PPState == 1 {
				targetSession.Ping2Time = time.Now()
			}
		}
		// Distribute chat message to provided user
		_ = WSSendBytes(targetSession.Conn, targetSession.Ctx, buf.Bytes())
		return
	}
	// Distribute SyncMessage to all members of this room
	server.SyncRoomsMu.RLock()
	room, ok := server.SyncRooms.Get(roomId)
	server.SyncRoomsMu.RUnlock()
	if !ok {
		return
	}
	room.Room.Mu.RLock()
	defer room.Room.Mu.RUnlock()
	for _, value := range room.Room.Sessions {
		if value.User.Username == msg.Username {
			// Do not distribute a message to the sender itself
			continue
		}
		value.Mu.RLock()
		_ = WSSendBytes(value.Conn, value.Ctx, buf.Bytes())
		value.Mu.RUnlock()
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

func handlePongResponse(s *SyncedSession) (string, *SyncedSession) {
	var targetSession *SyncedSession
	var act string
	if s.PPState == 0 {
		// Remember this time
		s.Pong1Time = time.Now()
		s.PPState = 1
		// ...and send another Ping
		targetSession = s
		act = "[s:A]"
	} else if s.PPState == 1 {
		// Remember this time
		s.Pong2Time = time.Now()
		// ...and calculate the latency
		d1 := s.Pong1Time.Sub(s.Ping1Time)
		d2 := s.Pong2Time.Sub(s.Ping2Time)
		// Get average for both deltas and set it as the current latency
		s.LatencyMS = (float32(d1.Milliseconds()) + float32(d2.Milliseconds())) / float32(2)
		// Send back latency to client
		targetSession = s
		act = fmt.Sprintf("[s:L]%f", s.LatencyMS)
	}
	return act, targetSession
}

func handleSetRoomName(server *SyncRoomServer, s *SyncedSession, text string) (string, *SyncedSession) {
	var targetSession *SyncedSession
	var act string
	// Only allow this action for the owner of this room
	server.SyncRoomsMu.RLock()
	room, ok := server.SyncRooms.Get(s.RoomId)
	server.SyncRoomsMu.RUnlock()
	if !ok {
		targetSession = s
		act = "[s:ERR]404;Room Not Found"
	}
	if room.Room.RoomOwner != s.User.Username {
		targetSession = s
		act = "[s:ERR]403;Forbidden"
	} else {
		// Change the room's name
		server.SyncRoomsMu.Lock()
		room, ok = server.SyncRooms.Get(s.RoomId)
		if ok {
			room.Room.Name = text[12:]
			server.SyncRooms.Set(s.RoomId, room)
			targetSession = s
			act = "[s:ANS]200;Name Changed"
		}
		server.SyncRoomsMu.Unlock()
	}
	return act, targetSession
}

func handleSetRoomData(server *SyncRoomServer, s *SyncedSession, text string) (string, *SyncedSession) {
	var targetSession *SyncedSession
	var act string
	// Request needs to be in the format: KEY;VALUE
	data := strings.SplitN(text[12:], ";", 2)
	if len(data) < 2 {
		server.SyncRoomsMu.Unlock()
		targetSession = s
		act = "[s:ERR]400;Wrong Format Expected KEY;VALUE"
		return act, targetSession
	}
	server.SyncRoomsMu.Lock()
	room, ok := server.SyncRooms.Get(s.RoomId)
	if ok {
		if len(room.Room.Data) >= 10_000 {
			server.SyncRoomsMu.Unlock()
			targetSession = s
			act = "[s:ERR]405;Max Data Amount Exceeded (Max 10k)"
			return act, targetSession
		}
		// Update data map with request payload for request data key
		room.Room.Data[data[0]] = data[1]
		server.SyncRooms.Set(s.RoomId, room)
		// Remember client as owner of data key
		keys, ok := room.Room.DataOwners[s.User.Username]
		if ok {
			if !slices.Contains(keys, data[0]) {
				keys = append(keys, data[0])
			}
		} else {
			keys = []string{data[0]}
		}
		room.Room.DataOwners[s.User.Username] = keys
		// Reply
		targetSession = s
		act = "[s:ANS]200;Data Set"
	}
	server.SyncRoomsMu.Unlock()
	return act, targetSession
}

func handleGetRoomData(server *SyncRoomServer, s *SyncedSession, text string) (string, *SyncedSession) {
	var targetSession *SyncedSession
	var act string
	// Request needs to be in the format: KEY
	key := text[12:]
	if len(key) < 1 {
		targetSession = s
		act = "[s:ERR]400;Wrong Format Expected KEY"
	} else {
		server.SyncRoomsMu.RLock()
		room, ok := server.SyncRooms.Get(s.RoomId)
		if ok {
			// Retrieve data for provided key and check if it exists
			val, ok := room.Room.Data[key]
			if ok {
				targetSession = s
				act = fmt.Sprintf("[s:DAT]%s;%s", key, val)
			} else {
				targetSession = s
				act = fmt.Sprintf("[s:ERR]400;Data Key %s Not Found", key)
			}
		}
		server.SyncRoomsMu.RUnlock()
	}
	return act, targetSession
}

func handleGetRoomSessions(server *SyncRoomServer, s *SyncedSession, text string) (string, *SyncedSession, bool) {
	var targetSession *SyncedSession
	var act string
	var sessionSum SyncedSessionSum
	server.SyncRoomsMu.RLock()
	defer server.SyncRoomsMu.RUnlock()
	room, ok := server.SyncRooms.Get(s.RoomId)
	if !ok {
		return "", nil, true
	}
	room.Room.Mu.RLock()
	defer room.Room.Mu.RUnlock()
	if text[12:] == "DIST" {
		// Distribute room sessions to all users (performance)
		for _, sesh := range room.Room.Sessions {
			sesh.Mu.RLock()
			// Generate session summary
			sessionSum = SyncedSessionSum{
				Username:  sesh.User.Username,
				LatencyMS: sesh.LatencyMS,
				IsOwner:   sesh.User.Username == room.Room.RoomOwner,
			}
			// Encode summary to JSON
			buf := &bytes.Buffer{}
			enc := json.NewEncoder(buf)
			enc.SetEscapeHTML(true)
			if err := enc.Encode(sessionSum); err != nil {
				sesh.Mu.RUnlock()
				continue
			}
			// Append JSON to message
			act = fmt.Sprintf("[s:SESH]%s", buf.Bytes())
			msg := &SyncMessage{
				Text:     text,
				Username: s.User.Username,
				Action:   act,
			}
			// ...and encode it as JSON, too
			buf = &bytes.Buffer{}
			enc = json.NewEncoder(buf)
			enc.SetEscapeHTML(true)
			if err := enc.Encode(msg); err != nil {
				sesh.Mu.RUnlock()
				continue
			}
			sesh.Mu.RUnlock()
			// Send message to all members
			for _, seshTarget := range room.Room.Sessions {
				seshTarget.Mu.RLock()
				_ = WSSendBytes(seshTarget.Conn, seshTarget.Ctx, buf.Bytes())
				seshTarget.Mu.RUnlock()
			}
		}
	} else {
		// Send room sessions to client
		for _, sesh := range room.Room.Sessions {
			sesh.Mu.RLock()
			// Generate session summary
			sessionSum = SyncedSessionSum{
				Username:  sesh.User.Username,
				LatencyMS: sesh.LatencyMS,
				IsOwner:   sesh.User.Username == room.Room.RoomOwner,
			}
			// Encode summary to JSON
			buf := &bytes.Buffer{}
			enc := json.NewEncoder(buf)
			enc.SetEscapeHTML(true)
			if err := enc.Encode(sessionSum); err != nil {
				sesh.Mu.RUnlock()
				continue
			}
			// Append JSON to message and send it to the client
			targetSession = s
			act = fmt.Sprintf("[s:SESH]%s", buf.Bytes())
			msg := &SyncMessage{
				Text:     text,
				Username: s.User.Username,
				Action:   act,
			}
			sesh.Mu.RUnlock()
			go server.DistributeSyncedMessageJSON(s.RoomId, &SyncMessageContainer{SyncMessage: msg}, targetSession)
		}
	}
	return act, targetSession, true
}

func handleGetRoomSessionData(server *SyncRoomServer, s *SyncedSession, text string) (string, *SyncedSession, bool) {
	var act string
	var sessionSum SyncedSessionDataSum
	var keys []string
	var data string
	// Retrieve room to iterate over all sessions
	server.SyncRoomsMu.RLock()
	defer server.SyncRoomsMu.RUnlock()
	room, ok := server.SyncRooms.Get(s.RoomId)
	if !ok {
		return "", nil, true
	}
	room.Room.Mu.RLock()
	defer room.Room.Mu.RUnlock()
	var filter = ""
	var fLen = 0
	if len(text) > 12 {
		// E.g.: [c:GET;UDAT]POS to filter all position data
		// ...(assuming it was saved with a key starting with POS like POS-wiki)
		filter = text[12:]
		fLen = len(filter)
	}
	// Distribute all room sessions' data to all users
	for _, sesh := range room.Room.Sessions {
		sesh.Mu.RLock()
		// Generate session data summary for each data key there is for this session
		keys, ok = room.Room.DataOwners[sesh.User.Username]
		if !ok {
			sesh.Mu.RUnlock()
			continue
		}
		for _, key := range keys {
			if fLen > 0 && key[0:fLen] != filter {
				// Filters out irrelevant keys by checking if their beginnings match
				// E.g.: Filter       Key
				//       POS    ->    POS-wiki
				//       123          123
				//       POS    ==    POS
				//       This key would be relevant thus not being skipped
				continue
			}
			data, ok = room.Room.Data[key]
			if !ok {
				continue
			}
			sessionSum = SyncedSessionDataSum{
				Username: sesh.User.Username,
				Key:      key,
				Value:    data,
			}
			// Encode summary to JSON
			buf := &bytes.Buffer{}
			enc := json.NewEncoder(buf)
			enc.SetEscapeHTML(true)
			if err := enc.Encode(sessionSum); err != nil {
				continue
			}
			// Append JSON to message
			act = fmt.Sprintf("[s:UDAT]%s", buf.Bytes())
			msg := &SyncMessage{
				Text:     text,
				Username: s.User.Username,
				Action:   act,
			}
			// ...and encode it as JSON, too
			buf = &bytes.Buffer{}
			enc = json.NewEncoder(buf)
			enc.SetEscapeHTML(true)
			if err := enc.Encode(msg); err != nil {
				continue
			}
			// Send message to all members
			lock := false
			for _, seshTarget := range room.Room.Sessions {
				if seshTarget.User.Username != sesh.User.Username {
					lock = true
					seshTarget.Mu.RLock()
				} else {
					lock = false
				}
				_ = WSSendBytes(seshTarget.Conn, seshTarget.Ctx, buf.Bytes())
				if lock {
					seshTarget.Mu.RUnlock()
				}
			}
		}
		sesh.Mu.RUnlock()
	}
	return "", nil, true
}

func handleDisconnectUser(server *SyncRoomServer, s *SyncedSession, text string) (string, *SyncedSession) {
	var targetSession *SyncedSession
	var act string
	// Only allow this action for the owner of this room
	server.SyncRoomsMu.RLock()
	defer server.SyncRoomsMu.RUnlock()
	room, ok := server.SyncRooms.Get(s.RoomId)
	if !ok {
		targetSession = s
		act = "[s:ERR]404;Room Not Found"
		return act, targetSession
	}
	room.Room.Mu.RLock()
	defer room.Room.Mu.RUnlock()
	if room.Room.RoomOwner != s.User.Username {
		targetSession = s
		act = "[s:ERR]403;Forbidden"
		return act, targetSession
	}
	// Retrieve and close session
	var target *SyncedSession
	if target, ok = room.Room.Sessions[text[6:]]; !ok {
		targetSession = s
		act = "[s:ERR]404;User Not Found"
		return act, targetSession
	}
	err := target.Conn.CloseNow()
	if err != nil {
		targetSession = s
		act = "[s:ERR]500;Error Disconnecting User: " + err.Error()
		return act, targetSession
	}
	return act, targetSession
}

func SendMsg(s *SyncedSession, text, message string) {
	msg := &SyncMessage{
		Text:     text,
		Username: s.User.Username,
		Action:   message,
	}
	_ = WSSendJSON(s.Conn, s.Ctx, msg)
}

// GetRoom retrieves the SyncRoom attached to a SyncedSession instance.
// To allow for performant access (e.g. retrieving the room for message distribution)
// ...this method first checks the cached SyncRoom before attempting to read from the SyncRoomServer itself.
func (s *SyncedSession) GetRoom(server *SyncRoomServer) (*SyncRoom, bool) {
	s.Mu.RLock()
	if s.RoomId == "" {
		s.Mu.RUnlock()
		return nil, false
	}
	// Check cache
	if s.Room != nil {
		s.Mu.RUnlock()
		return s.Room, true
	}
	// Attempt to update cache
	server.SyncRoomsMu.RLock()
	defer server.SyncRoomsMu.RUnlock()
	room, ok := server.SyncRooms.Get(s.RoomId)
	s.Mu.RUnlock()
	if !ok {
		return nil, false
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	s.Room = room.Room
	return s.Room, true
}
