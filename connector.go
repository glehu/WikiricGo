package main

import (
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

type CSession struct {
	User   *User
	Conn   *websocket.Conn
	Ctx    context.Context
	Status string
}

type Connector struct {
	SessionsMu     *sync.RWMutex
	Sessions       *btree.Map[string, *CSession] // Key = Username Value = CSession
	tokenAuth      *jwtauth.JWTAuth
	notificationDB *GoDB
}

type ConnectorMsg struct {
	Type          string `json:"typ"`
	Action        string `json:"act"`
	ReferenceUUID string `json:"pid"`
	Username      string `json:"usr"`
	Message       string `json:"msg"`
}

func CreateConnector(notificationDB *GoDB) *Connector {
	var connector = &Connector{
		SessionsMu:     &sync.RWMutex{},
		Sessions:       btree.NewMap[string, *CSession](3),
		notificationDB: notificationDB,
	}
	return connector
}

// PublicConnectorEndpoint will manage all websocket connections
func (connector *Connector) PublicConnectorEndpoint(
	r chi.Router,
	tokenAuth *jwtauth.JWTAuth,
	dbList *Databases,
) {
	connector.tokenAuth = tokenAuth
	// Route
	r.HandleFunc(
		"/ws/connector",
		connector.handleConnectorEndpoint(
			dbList,
		),
	)
}

func (connector *Connector) handleConnectorEndpoint(dbList *Databases) http.HandlerFunc {
	return func(
		w http.ResponseWriter,
		r *http.Request,
	) {
		ctx := r.Context()
		// Accept websocket connection to check token
		c, err := websocket.Accept(
			w,
			r,
			&websocket.AcceptOptions{InsecureSkipVerify: true}, // DEBUG
		)
		if err != nil {
			return
		}
		validToken, token := connector.checkToken(
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
		// Retrieve user
		username := usernameTmp.(string)
		user := dbList.Map["main"].ReadUserFromUsername(username)
		if user == nil {
			_ = c.Close(
				http.StatusUnauthorized,
				http.StatusText(http.StatusUnauthorized),
			)
			return
		}
		// Say hi!
		str := fmt.Sprintf("[s:wlcm]")
		err = c.Write(
			ctx,
			1, // 1=Text
			[]byte(str),
		)
		if err != nil {
			return
		}
		connector.SessionsMu.Lock()
		// Before adding the connector session, check if session existed before
		if _, didExist := connector.Sessions.Get(username); !didExist {
			// Session did not exist before, so notify others
			go func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Println("!! ERROR Recovered on notifyStatusChange", r)
					}
				}()
				dbList.Map["main"].notifyStatusChange(connector, username, "online")
			}()
		}
		// Add session to connector sessions
		session := &CSession{
			User:   user,
			Conn:   c,
			Ctx:    ctx,
			Status: "online",
		}
		connector.Sessions.Set(username, session)
		connector.SessionsMu.Unlock()
		// Handle connection
		connector.handleChatSession(session, dbList.Map["main"])
	}
}

func (db *GoDB) notifyStatusChange(connector *Connector, username string, status string) {
	if username == "" || status == "" {
		return
	}
	var err error
	var resp chan []*EntryResponse
	var response []*EntryResponse
	// Retrieve friends
	resp, err = db.Select(MemberDB, map[string]string{
		"user-friend": FIndex(username),
	}, nil)
	if err != nil {
		return
	}
	response = <-resp
	if len(response) < 1 {
		return
	}
	connector.SessionsMu.RLock()
	// Notify friends
	var sesh *CSession
	var ok bool
	var chatMember *ChatMember
	cMsg := &ConnectorMsg{
		Type:          "[s:ustat]",
		Action:        "update",
		ReferenceUUID: "",
		Username:      username,
		Message:       status,
	}
	for _, entry := range response {
		chatMember = &ChatMember{}
		err = json.Unmarshal(entry.Data, chatMember)
		if err == nil {
			// Check if friend is online by checking his connector session
			sesh, ok = connector.Sessions.Get(chatMember.Username)
			if ok {
				_ = WSSendJSON(sesh.Conn, sesh.Ctx, cMsg)
			}
		}
	}
	connector.SessionsMu.RUnlock()
}

func (connector *Connector) checkToken(c *websocket.Conn, ctx context.Context) (bool, jwt.Token) {
	// Listen for message
	typ, msg, err := c.Read(ctx)
	if err != nil {
		return false, nil
	}
	// Check JWT Token
	token, err := connector.tokenAuth.Decode(string(msg))
	if err != nil {
		return false, nil
	}
	// Check token's expiry date
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

func (connector *Connector) handleChatSession(s *CSession, db *GoDB) {
	messages, closed := ListenToMessages(
		s.Conn,
		s.Ctx,
	)
	for {
		select {
		case <-closed:
			connector.dropConnection(s, db)
			return
		case <-s.Ctx.Done():
			connector.dropConnection(s, db)
			return
		case resp := <-messages:
			if resp != nil {
				connector.handleIncomingMessage(
					s,
					resp,
				)
			}
		}
	}
}

func (connector *Connector) dropConnection(s *CSession, db *GoDB) {
	connector.SessionsMu.Lock()
	defer connector.SessionsMu.Unlock()
	connector.Sessions.Delete(s.User.Username)
	// Notify friends
	go db.notifyStatusChange(connector, s.User.Username, "offline")
}

const CForward = "[c:FWD]"

func (connector *Connector) handleIncomingMessage(
	s *CSession,
	resp *MessageResponse,
) {
	text := string(resp.Msg)
	if text == "" {
		return
	}
	cMsg := &ConnectorMsg{}
	err := json.Unmarshal([]byte(text), cMsg)
	if err != nil {
		return
	}
	// Forward?
	if cMsg.Action == CForward {
		connector.SessionsMu.RLock()
		defer connector.SessionsMu.RUnlock()
		user, ok := connector.Sessions.Get(cMsg.Username)
		if !ok {
			return
		}
		_ = user.Conn.Write(
			user.Ctx,
			resp.Typ,
			resp.Msg,
		)
	}
}
