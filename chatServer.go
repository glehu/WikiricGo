package main

import (
	"bytes"
	"context"
	"crypto/subtle"
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
	Username string
	Conn     *websocket.Conn
	Ctx      context.Context
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
		username, ok := token.Get("u_name")
		if !ok {
			_ = c.Close(
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			)
			return
		}
		// Check if chat group exists
		query := fmt.Sprintf(
			"^%s$",
			chatID,
		)
		resp, err := chatGroupDB.Select(
			map[string]string{
				"uuid": query,
			},
		)
		if err != nil {
			http.Error(
				w,
				http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError,
			)
			return
		}
		response := <-resp
		if len(response) < 1 {
			_ = c.Close(
				http.StatusNotFound,
				http.StatusText(http.StatusNotFound),
			)
			return
		}
		// Retrieve chat group from database
		chatGroup := &ChatGroup{}
		err = json.Unmarshal(
			response[0].Data,
			chatGroup,
		)
		if err != nil {
			http.Error(
				w,
				http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError,
			)
			return
		}
		// Is this a sub chat group? If so, then retrieve the main chat group
		if chatGroup.ParentUUID != "" {
			chatID = chatGroup.ParentUUID
			query = fmt.Sprintf(
				"^%s$",
				chatID,
			)
			resp, err = chatGroupDB.Select(
				map[string]string{
					"uuid": query,
				},
			)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}
			response = <-resp
			if len(response) < 1 {
				_ = c.Close(
					http.StatusNotFound,
					http.StatusText(http.StatusNotFound),
				)
				return
			}
			// Retrieve chat group from database
			chatGroup = &ChatGroup{}
			err = json.Unmarshal(
				response[0].Data,
				chatGroup,
			)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}
		}
		// Retrieve chat member
		query = fmt.Sprintf(
			"^%s-%s$",
			chatID,
			username,
		)
		resp, err = chatMemberDB.Select(
			map[string]string{
				"chat-user": query,
			},
		)
		if err != nil {
			http.Error(
				w,
				http.StatusText(http.StatusInternalServerError),
				http.StatusInternalServerError,
			)
			return
		}
		response = <-resp
		var chatMember *ChatMember
		if len(response) < 1 {
			// No user was found -> Is the chat group private? If not, join
			if chatGroup.IsPrivate {
				// Check if a password was provided in the url query
				password := r.URL.Query().Get("pw")
				isMatch := subtle.ConstantTimeCompare(
					[]byte(password),
					[]byte(chatGroup.Password),
				)
				if isMatch != 1 {
					_ = c.Close(
						http.StatusUnauthorized,
						http.StatusText(http.StatusUnauthorized),
					)
					return
				}
			}
			chatMember = &ChatMember{
				Username:             username.(string),
				ChatGroupUUID:        chatID,
				DisplayName:          username.(string),
				Roles:                []string{"member"},
				PublicKey:            "", // Public Key will be submitted by the client
				ThumbnailURL:         "",
				ThumbnailAnimatedURL: "",
				BannerURL:            "",
				BannerAnimatedURL:    "",
			}
			newMember, err := json.Marshal(chatMember)
			_, err = chatMemberDB.Insert(
				newMember,
				map[string]string{
					"chat-user": fmt.Sprintf(
						"%s-%s",
						chatID,
						username.(string),
					),
				},
			)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}
		} else {
			// Retrieve user from database
			chatMember = &ChatMember{}
			err = json.Unmarshal(
				response[0].Data,
				chatMember,
			)
			if err != nil {
				http.Error(
					w,
					http.StatusText(http.StatusInternalServerError),
					http.StatusInternalServerError,
				)
				return
			}
		}
		server.ChatGroupsMu.Lock()
		sessions, ok := server.ChatGroups.Get(chatIDOriginal)
		if ok {
			sessions[chatMember.Username] = &Session{
				Username: chatMember.Username,
				Conn:     c,
				Ctx:      ctx,
			}
		} else {
			server.ChatGroups.Set(
				chatIDOriginal,
				map[string]*Session{
					chatMember.Username: {
						Username: chatMember.Username,
						Conn:     c,
						Ctx:      ctx,
					},
				},
			)
		}
		server.ChatGroupsMu.Unlock()
		// Replace chatID with original chatID to preserve access to sub chat groups
		chatMember.ChatGroupUUID = chatIDOriginal
		server.handleChatSession(
			c,
			ctx,
			chatMember,
		)
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

func (server *ChatServer) handleChatSession(
	c *websocket.Conn,
	ctx context.Context,
	user *ChatMember,
) {
	messages := listenToMessages(
		c,
		ctx,
	)
	for {
		select {
		case resp := <-messages:
			server.handleIncomingMessage(
				c,
				ctx,
				resp,
				user,
			)
			break
		case <-ctx.Done():
			server.ChatGroupsMu.Lock()
			sessions, ok := server.ChatGroups.Get(user.ChatGroupUUID)
			if ok {
				sessions[user.Username] = nil
			}
			server.ChatGroupsMu.Unlock()
			return
		}
	}
}

func (server *ChatServer) handleIncomingMessage(
	c *websocket.Conn,
	ctx context.Context,
	resp *MessageResponse,
	user *ChatMember,
) {
	msg := &ChatMessage{
		ChatGroupUUID: user.ChatGroupUUID,
		Text:          string(resp.Msg),
		Username:      user.Username,
		TimeCreated:   TimeNowIsoString(),
	}
	go server.DistributeChatMessageJSON(msg)
	jsonEntry, err := json.Marshal(msg)
	if err != nil {
		return
	}
	_, _ = server.DB.Insert(jsonEntry, map[string]string{
		"chatID": user.ChatGroupUUID,
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
