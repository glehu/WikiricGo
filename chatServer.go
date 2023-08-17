package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/gofrs/uuid"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/tidwall/btree"
	"net/http"
	"nhooyr.io/websocket"
	"time"
)

type Session struct {
	userUUID uuid.UUID
	username string
	conn     *websocket.Conn
}

type ChatServer struct {
	Users     *btree.BTreeG[*Session]
	tokenAuth *jwtauth.JWTAuth
}

type MessageResponse struct {
	Typ websocket.MessageType
	Msg []byte
}

func CreateChatServer() *ChatServer {
	server := &ChatServer{
		Users: btree.NewBTreeG(userComparator),
	}
	return server
}

// WebsocketChatEndpoint will manage all websocket connections
func (server *ChatServer) WebsocketChatEndpoint(r chi.Router, tokenAuth *jwtauth.JWTAuth, userDB *GoDB) {
	server.tokenAuth = tokenAuth
	// Route
	r.HandleFunc("/ws/chat/{chatID}", server.handleChatEndpoint(userDB))
}

func (server *ChatServer) handleChatEndpoint(userDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		chatID := chi.URLParam(r, "chatID")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		validToken, token := server.checkToken(c, ctx)
		if !validToken {
			_ = c.Close(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			return
		}
		username, ok := token.Get("u_name")
		if !ok {
			_ = c.Close(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			return
		}
		// Check if this user exists
		query := fmt.Sprintf("^%s$", username)
		resp, err := userDB.Select(map[string]string{
			"username": query,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		if len(response) < 1 {
			_ = c.Close(http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized))
			return
		}
		user := &User{}
		err = json.Unmarshal(response[0].Data, user)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		server.handleChatSession(c, ctx, user)
	}
}

func (server *ChatServer) checkToken(c *websocket.Conn, ctx context.Context) (bool, jwt.Token) {
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
	userUuidTmp, _ := token.Get("u_uuid")
	userUuid, _ := uuid.FromString(userUuidTmp.(string))
	userName, _ := token.Get("u_name")
	// Say hi!
	str := fmt.Sprintf("wlcm %s (uuid:%s)!", userName, userUuid)
	err = c.Write(ctx, typ, []byte(str))
	if err != nil {
		return false, nil
	}
	return true, token
}

func (server *ChatServer) handleChatSession(c *websocket.Conn, ctx context.Context, user *User) {
	messages := listenToMessages(c, ctx)
	for {
		select {
		case resp := <-messages:
			server.handleIncomingMessage(c, ctx, resp, user)
			break
		case <-ctx.Done():
			return
		}
	}
}

func (server *ChatServer) handleIncomingMessage(c *websocket.Conn, ctx context.Context, resp *MessageResponse, user *User) {
	str := fmt.Sprintf("%s: %s", user.Username, resp.Msg)
	err := c.Write(ctx, resp.Typ, []byte(str))
	if err != nil {
		return
	}
}

func listenToMessages(c *websocket.Conn, ctx context.Context) chan *MessageResponse {
	resp := make(chan *MessageResponse)
	go func() {
		for {
			typ, msg, err := c.Read(ctx)
			if err != nil {
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

func userComparatorBackup(a, b *Session) bool {
	return a.userUUID.String() < b.userUUID.String()
}

func userComparator(a, b *Session) bool {
	if a.username < b.username {
		return true
	} else if a.username > b.username {
		return false
	}
	return userComparatorBackup(a, b)
}
