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

func (server *ChatServer) handleChatEndpoint(userDB, chatGroupDB, chatMessagesDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		ctx := r.Context()
		chatID := chi.URLParam(
			r,
			"chatID",
		)
		if chatID == "" {
			http.Error(
				w,
				http.StatusText(http.StatusBadRequest),
				http.StatusBadRequest,
			)
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
		validToken, token := server.checkToken(
			c,
			ctx,
		)
		if !validToken {
			_ = c.Close(
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			)
			return
		}
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
		chatGroup, chatMember, _, err := GetChatGroupAndMember(chatGroupDB, chatMemberDB, chatID, username, password)
		if chatMember == nil || err != nil {
			_ = c.Close(
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			)
			return
		}
		canWrite := CheckWriteRights(chatMember, chatGroup)
		canRead := CheckReadRights(chatMember, chatGroup)
		server.ChatGroupsMu.Lock()
		sessions, ok := server.ChatGroups.Get(chatIDOriginal)
		session := &Session{
			ChatMember: chatMember,
			Conn:       c,
			Ctx:        ctx,
			CanWrite:   canWrite,
			CanRead:    canRead,
		}
		if ok {
			sessions[chatMember.Username] = session
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
	c *websocket.Conn,
	ctx context.Context,
) (bool, jwt.Token) {
	// Listen for message
	typ, msg, err := c.Read(ctx)
	if err != nil {
		return false, nil
	}
	// Check JWT Token
	token, err := server.tokenAuth.Decode(string(msg))
	if err != nil {
		return false, nil
	}
	expTmp, ok := token.Get("exp")
	if ok != true {
		return false, nil
	}
	exp := expTmp.(time.Time)
	expired := exp.Compare(time.Now()) < 0
	if expired {
		return false, nil
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
		return false, nil
	}
	return true, token
}

func (server *ChatServer) handleChatSession(s *Session) {
	messages := listenToMessages(
		s.Conn,
		s.Ctx,
	)
	for {
		select {
		case resp := <-messages:
			server.handleIncomingMessage(
				s,
				resp,
			)
			break
		case <-s.Ctx.Done():
			server.ChatGroupsMu.Lock()
			sessions, ok := server.ChatGroups.Get(s.ChatMember.ChatGroupUUID)
			if ok {
				sessions[s.ChatMember.Username] = nil
			}
			server.ChatGroupsMu.Unlock()
			return
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
	msg := &ChatMessage{
		ChatGroupUUID: s.ChatMember.ChatGroupUUID,
		Text:          string(resp.Msg),
		Username:      s.ChatMember.Username,
		TimeCreated:   TimeNowIsoString(),
	}
	go server.DistributeChatMessageJSON(msg)
	jsonEntry, err := json.Marshal(msg)
	if err != nil {
		return
	}
	_, _ = server.DB.Insert(jsonEntry, map[string]string{
		"chatID": s.ChatMember.ChatGroupUUID,
	})
}

func (server *ChatServer) DistributeChatMessageJSON(msg *ChatMessage) {
	server.ChatGroupsMu.RLock()
	sessions, ok := server.ChatGroups.Get(msg.ChatGroupUUID)
	if ok {
		for _, value := range sessions {
			err := WSSendJSON(value.Conn, value.Ctx, msg)
			if err != nil {
				return
			}
		}
	}
	server.ChatGroupsMu.RUnlock()
}

func listenToMessages(
	c *websocket.Conn,
	ctx context.Context,
) chan *MessageResponse {
	resp := make(chan *MessageResponse)
	go func() {
		for {
			typ, msg, err := c.Read(ctx)
			if err != nil {
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
	return resp
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
