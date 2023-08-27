package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/tidwall/btree"
	"net/http"
	"nhooyr.io/websocket"
	"sync"
	"time"
)

type Session struct {
	ChatMember *ChatMember
	Conn       *websocket.Conn
	Ctx        context.Context
	R          *http.Request
	CanWrite   bool
	CanRead    bool
}

type ChatServer struct {
	ChatGroupsMu *sync.RWMutex
	ChatGroups   *btree.Map[string, map[string]*Session] // Key = ChatGroupUUID Value = Map of [Username]Sessions
	tokenAuth    *jwtauth.JWTAuth
	DB           *GoDB
}

type MessageResponse struct {
	Typ websocket.MessageType
	Msg []byte
}

func CreateChatServer(db *GoDB) *ChatServer {
	server := &ChatServer{
		ChatGroupsMu: &sync.RWMutex{},
		ChatGroups:   btree.NewMap[string, map[string]*Session](3),
		DB:           db,
	}
	return server
}

// PublicChatEndpoint will manage all websocket connections
func (server *ChatServer) PublicChatEndpoint(
	r chi.Router,
	tokenAuth *jwtauth.JWTAuth,
	userDB, chatGroupDB, chatMessagesDB, chatMemberDB *GoDB,
) {
	server.tokenAuth = tokenAuth
	// Route
	r.HandleFunc(
		"/ws/chat/{chatID}",
		server.handleChatEndpoint(
			userDB,
			chatGroupDB,
			chatMessagesDB,
			chatMemberDB,
		),
	)
}

func (server *ChatServer) handleChatEndpoint(
	userDB, chatGroupDB, chatMessagesDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		chatID := chi.URLParam(r, "chatID")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		chatIDOriginal := chatID
		// Accept websocket connection to check token
		c, err := websocket.Accept(
			w,
			r,
			nil,
		)
		if err != nil {
			return
		}
		validToken, token, r := server.checkToken(userDB, c, r)
		if !validToken {
			_ = c.Close(
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			)
			return
		}
		ctx := r.Context()
		usernameTmp, ok := token.Get("u_name")
		if !ok {
			_ = c.Close(
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			)
			return
		}
		username := usernameTmp.(string)
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		chatGroup, chatMember, _, err := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil, chatID, username, password, r)
		if chatMember == nil || err != nil {
			_ = c.Close(
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		canRead := CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
		server.ChatGroupsMu.Lock()
		sessions, ok := server.ChatGroups.Get(chatIDOriginal)
		session := &Session{
			ChatMember: chatMember.ChatMember,
			Conn:       c,
			Ctx:        ctx,
			R:          r,
			CanWrite:   canWrite,
			CanRead:    canRead,
		}
		if ok {
			sessions[chatMember.Username] = session
			server.ChatGroups.Set(chatIDOriginal, sessions)
		} else {
			server.ChatGroups.Set(
				chatIDOriginal,
				map[string]*Session{
					chatMember.Username: session,
				},
			)
		}
		server.ChatGroupsMu.Unlock()
		// Replace chatID with original chatID to preserve access to sub chat groups
		chatMember.ChatGroupUUID = chatIDOriginal
		server.handleChatSession(session)
	}
}

func (server *ChatServer) checkToken(
	userDB *GoDB,
	c *websocket.Conn,
	r *http.Request,
) (bool, jwt.Token, *http.Request) {
	// Listen for message
	ctx := r.Context()
	typ, msg, err := c.Read(ctx)
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
	// TODO
	userName, _ := token.Get("u_name")
	// Say hi!
	str := fmt.Sprintf(
		"wlcm %s!",
		userName,
	)
	err = c.Write(
		ctx,
		typ,
		[]byte(str),
	)
	if err != nil {
		return false, nil, nil
	}
	// Get client user
	userQuery := fmt.Sprintf("^%s$", userName)
	resp, err := userDB.Select(
		map[string]string{
			"username": userQuery,
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

func (server *ChatServer) handleChatSession(s *Session) {
	messages, closed := ListenToMessages(
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
				)
			}
		}
	}
}

func (server *ChatServer) dropConnection(s *Session) {
	server.ChatGroupsMu.Lock()
	defer server.ChatGroupsMu.Unlock()
	sessions, ok := server.ChatGroups.Get(s.ChatMember.ChatGroupUUID)
	if ok {
		delete(sessions, s.ChatMember.Username)
		// Are there any connections left? If not, then delete the chat session
		if len(sessions) < 1 {
			server.ChatGroups.Delete(s.ChatMember.ChatGroupUUID)
		} else {
			server.ChatGroups.Set(s.ChatMember.ChatGroupUUID, sessions)
		}
	}
}

func (server *ChatServer) handleIncomingMessage(
	s *Session,
	resp *MessageResponse,
) {
	if !s.CanWrite {
		return
	}
	text := string(resp.Msg)
	msg := &ChatMessage{
		ChatGroupUUID: s.ChatMember.ChatGroupUUID,
		Text:          text,
		Username:      s.ChatMember.Username,
		TimeCreated:   TimeNowIsoString(),
	}
	// [c:SC] is a prefix marking the message as pass through only without saving it
	uUID := ""
	if len(text) < 6 || text[0:6] != "[c:SC]" {
		jsonEntry, err := json.Marshal(msg)
		if err != nil {
			return
		}
		uUID, _ = server.DB.Insert(jsonEntry, map[string]string{
			"chatID": s.ChatMember.ChatGroupUUID,
		})
	}
	go server.DistributeChatMessageJSON(&ChatMessageContainer{
		ChatMessage: msg,
		UUID:        uUID,
	})
}

func (server *ChatServer) DistributeChatMessageJSON(msg *ChatMessageContainer) {
	server.ChatGroupsMu.RLock()
	sessions, ok := server.ChatGroups.Get(msg.ChatGroupUUID)
	if ok {
		for _, value := range sessions {
			_ = WSSendJSON(value.Conn, value.Ctx, msg) // TODO: Drop connection?
		}
	}
	server.ChatGroupsMu.RUnlock()
}

func (server *ChatServer) DistributeChatActionMessageJSON(msg *ChatActionMessage) {
	server.ChatGroupsMu.RLock()
	sessions, ok := server.ChatGroups.Get(msg.ChatGroupUUID)
	if ok {
		for _, value := range sessions {
			_ = WSSendJSON(value.Conn, value.Ctx, msg) // TODO: Drop connection?
		}
	}
	server.ChatGroupsMu.RUnlock()
}

func ListenToMessages(
	c *websocket.Conn,
	ctx context.Context,
) (chan *MessageResponse, chan bool) {
	// Prepare channels
	resp := make(chan *MessageResponse)
	closed := make(chan bool)
	// Launch goroutine with listening loop
	go func() {
		for {
			typ, msg, err := c.Read(ctx)
			if err != nil {
				closed <- true
				fmt.Println(
					"ws read error",
					err,
				)
				return
			}
			resp <- &MessageResponse{
				Typ: typ,
				Msg: msg,
			}
		}
	}()
	return resp, closed
}

func WSSendJSON(
	c *websocket.Conn,
	ctx context.Context,
	v interface{},
) error {
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return err
	}
	err := c.Write(
		ctx,
		websocket.MessageText,
		buf.Bytes(),
	)
	if err != nil {
		return err
	}
	return nil
}
