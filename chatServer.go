package main

import (
	"bytes"
	"context"
	"encoding/json"
	"firebase.google.com/go/messaging"
	"fmt"
	"github.com/dgraph-io/badger/v4"
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

type Session struct {
	ChatMember   *ChatMember
	Conn         *websocket.Conn
	Ctx          context.Context
	R            *http.Request
	CanWrite     bool
	CanRead      bool
	ChatName     string
	ChatParentID string
}

type ChatServer struct {
	ChatGroupsMu        *sync.RWMutex
	ChatGroups          *btree.Map[string, map[string]*Session]
	tokenAuth           *jwtauth.JWTAuth
	DB                  *GoDB
	NotificationCounter *atomic.Int64
}

type MessageResponse struct {
	Typ websocket.MessageType
	Msg []byte
}

type EditMessage struct {
	MessageID string `json:"uid"`
	Text      string `json:"text"`
}

type ReactionMessage struct {
	MessageID string `json:"uid"`
	Reaction  string `json:"type"`
}

func CreateChatServer(db *GoDB) *ChatServer {
	server := &ChatServer{
		ChatGroupsMu:        &sync.RWMutex{},
		ChatGroups:          btree.NewMap[string, map[string]*Session](3),
		DB:                  db,
		NotificationCounter: &atomic.Int64{},
	}
	return server
}

// PublicChatEndpoint will manage all websocket connections
func (server *ChatServer) PublicChatEndpoint(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
	dbList *Databases,
	connector *Connector, fcmClient *messaging.Client,
) {
	server.tokenAuth = tokenAuth
	// Route
	r.HandleFunc(
		"/ws/chat/{chatID}",
		server.handleChatEndpoint(
			dbList.Map["main"], dbList.Map["rapid"],
			connector, fcmClient,
		),
	)
}

func (server *ChatServer) handleChatEndpoint(
	mainDB, rapidDB *GoDB,
	connector *Connector, fcmClient *messaging.Client,
) http.HandlerFunc {
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
			&websocket.AcceptOptions{InsecureSkipVerify: true}, // DEBUG
		)
		if err != nil {
			return
		}
		validToken, token, r := server.checkToken(mainDB, c, r)
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
			mainDB, rapidDB, connector, chatID, username, password, r)
		if chatMember == nil || err != nil {
			_ = c.Close(
				http.StatusForbidden,
				http.StatusText(http.StatusForbidden),
			)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		canRead := CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
		// Say hi! Send write and read rights over the websocket connection
		str := fmt.Sprintf("[s:wlcm];%t;%t", canWrite, canRead)
		err = c.Write(
			ctx,
			1, // 1=Text
			[]byte(str),
		)
		if err != nil {
			return
		}
		server.ChatGroupsMu.Lock()
		sessions, ok := server.ChatGroups.Get(chatIDOriginal)
		session := &Session{
			ChatMember:   chatMember.ChatMember,
			Conn:         c,
			Ctx:          ctx,
			R:            r,
			CanWrite:     canWrite,
			CanRead:      canRead,
			ChatName:     chatGroup.Name,
			ChatParentID: chatGroup.ParentUUID,
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
		server.handleChatSession(session, mainDB, rapidDB, fcmClient)
	}
}

func (server *ChatServer) checkToken(
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

func (server *ChatServer) handleChatSession(s *Session,
	mainDB, rapidDB *GoDB, fcmClient *messaging.Client,
) {
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
					mainDB, rapidDB, fcmClient,
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
	mainDB, rapidDB *GoDB,
	fcmClient *messaging.Client,
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
	uUID := ""
	skipSave := false
	skipDist := false
	// [c:SC] is a prefix marking the message as pass through only without saving it
	if len(text) >= 6 && text[0:6] == "[c:SC]" {
		skipSave = true
	}
	// Command messages will also not be saved
	if len(text) >= 13 && text[0:13] == "[c:EDIT<JSON]" {
		skipSave = true
		skipDist = true
		server.handleEditMessage(s, text[13:], rapidDB)
	}
	if len(text) >= 14 && text[0:14] == "[c:REACT<JSON]" {
		skipSave = true
		skipDist = true
		server.handleReactMessage(s, text[14:], rapidDB)
	}
	if !skipSave {
		jsonEntry, err := json.Marshal(msg)
		if err != nil {
			return
		}
		uUID, _ = server.DB.Insert(MessageDB, jsonEntry, map[string]string{
			"chatID": s.ChatMember.ChatGroupUUID,
		})
		// Send notification
		go server.DistributeFCMMessage(s, msg, fcmClient, mainDB)
	}
	if !skipDist {
		go server.DistributeChatMessageJSON(&ChatMessageContainer{
			ChatMessage: msg,
			UUID:        uUID,
		})
	}
}

func (server *ChatServer) DistributeChatMessageJSON(msg *ChatMessageContainer) {
	server.ChatGroupsMu.RLock()
	sessions, ok := server.ChatGroups.Get(msg.ChatGroupUUID)
	server.ChatGroupsMu.RUnlock()
	if ok {
		for _, value := range sessions {
			_ = WSSendJSON(value.Conn, value.Ctx, msg) // TODO: Drop connection?
		}
	}
}

func (server *ChatServer) DistributeChatActionMessageJSON(msg *ChatActionMessage) {
	server.ChatGroupsMu.RLock()
	sessions, ok := server.ChatGroups.Get(msg.ChatGroupUUID)
	server.ChatGroupsMu.RUnlock()
	if ok {
		for _, value := range sessions {
			_ = WSSendJSON(value.Conn, value.Ctx, msg) // TODO: Drop connection?
		}
	}
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

func (server *ChatServer) handleEditMessage(s *Session, text string, rapidDB *GoDB) {
	editMessage := &EditMessage{}
	err := json.Unmarshal([]byte(text), editMessage)
	if err != nil {
		return
	}
	// Get message
	resp, txn := rapidDB.Get(MessageDB, editMessage.MessageID)
	defer txn.Discard()
	request := &ChatMessage{}
	err = json.Unmarshal(resp.Data, request)
	if err != nil {
		return
	}
	// Initialize message
	request.Username = s.ChatMember.Username
	request.Text = editMessage.Text
	request.WasEdited = true // Edited!
	// Distribute action message
	actionMessage := &ChatActionMessage{
		ChatMessageContainer: &ChatMessageContainer{
			ChatMessage: request,
			Analytics:   nil,
			UUID:        resp.uUID,
		},
		Action: "edit",
	}
	go server.DistributeChatActionMessageJSON(actionMessage)
	// Are we editing or actually deleting?
	if editMessage.Text == "" {
		// Delete message
		txn.Discard()
		err = rapidDB.Delete(MessageDB, editMessage.MessageID, []string{"chatID"})
		if err != nil {
			return
		}
	} else {
		// Store message
		jsonMessage, err := json.Marshal(request)
		if err != nil {
			fmt.Println(err)
			return
		}
		err = rapidDB.Update(MessageDB, txn, resp.uUID, jsonMessage, map[string]string{
			"chatID": request.ChatGroupUUID,
		})
	}
}

func (server *ChatServer) handleReactMessage(s *Session, text string, rapidDB *GoDB) {
	editMessage := &ReactionMessage{}
	err := json.Unmarshal([]byte(text), editMessage)
	if err != nil {
		return
	}
	// Get message
	messageBytes, txnMsg := rapidDB.Get(MessageDB, editMessage.MessageID)
	defer txnMsg.Discard()
	message := &ChatMessage{}
	err = json.Unmarshal(messageBytes.Data, message)
	if err != nil {
		return
	}
	analyticsUpdate := false
	var analytics *Analytics
	var analyticsBytes *EntryResponse
	var txn *badger.Txn
	if message.AnalyticsUUID != "" {
		analyticsBytes, txn = rapidDB.Get(AnaDB, message.AnalyticsUUID)
		if txn != nil {
			defer txn.Discard()
			analytics = &Analytics{}
			err = json.Unmarshal(analyticsBytes.Data, analytics)
			if err != nil {
				// Could not retrieve analytics -> Create new one
				analytics = nil
			} else {
				analyticsUpdate = true
			}
		}
	}
	// Create analytics if there are none
	reactionRemoved := false
	if analytics == nil {
		analytics = &Analytics{
			Views:     0,
			Reactions: make([]Reaction, 1),
			Downloads: 0,
			Bookmarks: 0,
		}
		// analytics.Reactions[editMessage.Reaction] = []string{s.ChatMember.Username}
		analytics.Reactions[0] = Reaction{
			Type:      editMessage.Reaction,
			Usernames: []string{s.ChatMember.Username},
		}
	} else {
		// Check if reaction is present already, if yes -> remove (toggle functionality)
		indexReaction := -1
		indexUser := -1
		for i, r := range analytics.Reactions {
			if r.Type == editMessage.Reaction {
				indexReaction = i
				// Find user
				for ix, rUser := range r.Usernames {
					if rUser == s.ChatMember.Username {
						// Found -> Remove
						indexUser = ix
						break
					}
				}
				break
			}
		}
		if indexReaction != -1 {
			reactions := analytics.Reactions[indexReaction]
			if indexUser != -1 {
				// Delete
				reactions.Usernames = append(reactions.Usernames[:indexUser], reactions.Usernames[indexUser+1:]...)
				reactionRemoved = true
			} else {
				// Append
				reactions.Usernames = append(reactions.Usernames, s.ChatMember.Username)
			}
			analytics.Reactions[indexReaction] = reactions
		} else {
			// No reaction of this type existed yet
			// analytics.Reactions[editMessage.Reaction] = []string{s.ChatMember.Username}
			analytics.Reactions = append(analytics.Reactions, Reaction{
				Type:      editMessage.Reaction,
				Usernames: []string{s.ChatMember.Username},
			})
		}
	}
	// Distribute action message
	actionMsg := &ChatMessage{}
	actionMsg.Username = s.ChatMember.Username // User that reacted
	actionMsg.Text = editMessage.Reaction      // Reaction as msg
	actionMsg.TimeCreated = ""
	actionMsg.WasEdited = reactionRemoved // Edit=true if reaction existed before thus was removed
	actionMsg.ChatGroupUUID = message.ChatGroupUUID
	container := &ChatMessageContainer{
		ChatMessage: actionMsg,
		UUID:        messageBytes.uUID,
	}
	actionMessage := &ChatActionMessage{
		ChatMessageContainer: container,
		Action:               "react",
	}
	go server.DistributeChatActionMessageJSON(actionMessage)
	// Save
	analyticsJson, err := json.Marshal(analytics)
	if err != nil {
		return
	}
	// Commit changes
	if analyticsUpdate && analyticsBytes != nil {
		// Analytics existed -> Update them
		err = rapidDB.Update(AnaDB, txn, analyticsBytes.uUID, analyticsJson, map[string]string{})
		if err != nil {
			return
		}
	} else {
		// Insert analytics while returning its UUID to the message for reference
		message.AnalyticsUUID, err = rapidDB.Insert(AnaDB, analyticsJson, map[string]string{})
		if err != nil {
			return
		}
		// Update message
		messageJson, err := json.Marshal(message)
		if err != nil {
			return
		}
		err = rapidDB.Update(MessageDB, txnMsg, messageBytes.uUID, messageJson, map[string]string{})
		if err != nil {
			return
		}
	}
}

func (server *ChatServer) DistributeFCMMessage(s *Session, msg *ChatMessage, fcmClient *messaging.Client,
	mainDB *GoDB,
) {
	if fcmClient == nil {
		return
	}
	// Retrieve members of main chatroom
	// Check if we're targeting a sub chat since only main chat rooms have members technically
	mainChatGroup, ok := mainDB.GetMainChatGroup(msg.ChatGroupUUID)
	if !ok {
		return
	}
	// Retrieve chat members
	query := FIndex(mainChatGroup.UUID)
	resp, err := mainDB.Select(MemberDB,
		map[string]string{
			"chat-usr": query,
		}, nil,
	)
	if err != nil {
		return
	}
	responseMember := <-resp
	if len(responseMember) < 1 {
		return
	}
	// Retrieve connected users (we may not notify those under specific circumstances)
	server.ChatGroupsMu.RLock()
	sessions, ok := server.ChatGroups.Get(msg.ChatGroupUUID)
	server.ChatGroupsMu.RUnlock()
	if !ok {
		return
	}
	// Check what members we are going to notify
	var chatMember *ChatMember
	tokens := make([]string, 0)
	i := 0
	for _, value := range responseMember {
		chatMember = &ChatMember{}
		err = json.Unmarshal(value.Data, chatMember)
		// Skip if json unmarshal failed, members has no FCM subscription or if we're looking at the sender
		if err != nil || chatMember.FCMToken == "" || chatMember.Username == msg.Username {
			continue
		}
		// Is this member currently connected to this chat group?
		if sessions[chatMember.Username] != nil {
			// TODO: Check if this member is inactive (maybe?)
			continue
		}
		// Append token as we are going to notify this member
		tokens = append(tokens, chatMember.FCMToken)
		i += 1
		if i >= 500 {
			// FCM only allows up to 500 recipients
			break
		}
	}
	if i < 1 {
		return
	}
	// Set notification link data
	destinationID := msg.ChatGroupUUID
	subchatID := ""
	if s.ChatParentID != "" {
		// If the message is targeting a subchat, set its parent as the destination instead
		// The subchat will be referenced, too, but the starting point will be the parent
		destinationID = s.ChatParentID
		subchatID = msg.ChatGroupUUID
	}
	_, _ = fcmClient.SendMulticast(context.Background(), &messaging.MulticastMessage{
		Notification: &messaging.Notification{
			Title: s.ChatName,
			Body:  fmt.Sprintf("%s has sent a message!", s.ChatMember.DisplayName),
		},
		Data: map[string]string{
			"dlType":      "clarifier",
			"dlDest":      fmt.Sprintf("/apps/clarifier/wss/%s", destinationID),
			"subchatGUID": subchatID,
		},
		Webpush: &messaging.WebpushConfig{
			FcmOptions: &messaging.WebpushFcmOptions{
				Link: fmt.Sprintf("/apps/clarifier/wss/%s", destinationID),
			},
		},
		Tokens: tokens,
	})
}
