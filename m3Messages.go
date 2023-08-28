package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
	"strings"
)

type ChatMessage struct {
	ChatGroupUUID string `json:"pid"`
	Text          string `json:"msg"`
	Username      string `json:"usr"`
	TimeCreated   string `json:"ts"`
	WasEdited     bool   `json:"e"`
	AnalyticsUUID string `json:"ana"` // Views, likes etc. will be stored in a separate database
}

type ChatMessageReaction struct {
	Reaction string `json:"reaction"`
}

type ChatMessageContainer struct {
	*ChatMessage
	*Analytics
	UUID string
}

type ChatMessagesResponse struct {
	Messages []*ChatMessageContainer `json:"messages"`
}

type ChatActionMessage struct {
	*ChatMessageContainer
	Action string `json:"action"`
}

func OpenChatMessageDatabase() *GoDB {
	db := OpenDB(
		"chatMessages", []string{
			"chatID",
		},
	)
	return db
}

func (db *GoDB) ProtectedChatMessagesEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth, chatServer *ChatServer, chatGroupDB, chatMemberDB, analyticsDB *GoDB,
) {
	r.Route("/msg/private", func(r chi.Router) {
		r.Post("/create", db.handleChatMessageCreate(chatServer, chatGroupDB, chatMemberDB))
		r.Post("/edit/{msgID}", db.handleChatMessageEdit(chatServer, chatGroupDB, chatMemberDB))
		r.Post("/react/{msgID}", db.handleChatMessageReaction(chatServer, chatGroupDB, chatMemberDB, analyticsDB))
		r.Get("/delete/{msgID}", db.handleChatMessageDelete(chatServer, chatGroupDB, chatMemberDB))
		r.Route("/chat", func(r chi.Router) {
			r.Get("/get/{chatID}", db.handleChatMessageFromChat(chatServer, chatGroupDB, chatMemberDB, analyticsDB))
		})
	})
}

func (db *GoDB) handleChatMessageCreate(chatServer *ChatServer, chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &ChatMessage{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		chatGroup, chatMember, _, _ := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			request.ChatGroupUUID, user.Username, password, r)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Initialize message
		request.TimeCreated = TimeNowIsoString()
		request.Username = user.Username
		request.WasEdited = false
		// Store message
		jsonMessage, err := json.Marshal(request)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(
			jsonMessage, map[string]string{
				"chatID": request.ChatGroupUUID,
			},
		)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
		// Distribute message
		go chatServer.DistributeChatMessageJSON(&ChatMessageContainer{
			ChatMessage: request,
			UUID:        uUID,
		})
	}
}

func (db *GoDB) handleChatMessageEdit(chatServer *ChatServer, chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &ChatMessageContainer{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		chatGroup, chatMember, _, _ := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			request.ChatGroupUUID, user.Username, password, r)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Initialize message
		request.TimeCreated = TimeNowIsoString()
		request.Username = user.Username
		request.WasEdited = true // Edited!
		// Distribute action message
		actionMessage := &ChatActionMessage{
			ChatMessageContainer: request,
			Action:               "edit",
		}
		go chatServer.DistributeChatActionMessageJSON(actionMessage)
		// Store message
		jsonMessage, err := json.Marshal(request)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(
			request.UUID, jsonMessage, "", map[string]string{
				"chatID": request.ChatGroupUUID,
			},
		)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, request.UUID)
	}
}

func (a *ChatMessage) Bind(_ *http.Request) error {
	if a.Text == "" {
		return errors.New("missing text")
	}
	if a.ChatGroupUUID == "" {
		return errors.New("missing parent")
	}
	return nil
}

func (a *ChatMessageReaction) Bind(_ *http.Request) error {
	if a.Reaction == "" {
		return errors.New("missing reaction")
	}
	return nil
}

func (db *GoDB) handleChatMessageFromChat(
	chatServer *ChatServer, chatGroupDB, chatMemberDB, analyticsDB *GoDB,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		chatID := chi.URLParam(r, "chatID")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		chatGroup, chatMember, _, err := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			chatID, user.Username, password, r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if chatGroup == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		// Check rights
		canRead := CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Options?
		options := r.Context().Value("pagination").(*SelectOptions)
		if options.MaxResults <= 0 {
			options.MaxResults = 50
		}
		// Retrieve messages from this chat group
		resp, err := db.Select(map[string]string{
			"chatID": chatID,
		}, options)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		messages := ChatMessagesResponse{Messages: make([]*ChatMessageContainer, len(response))}
		if len(response) < 1 {
			render.JSON(w, r, messages)
			return
		}
		for i, result := range response {
			msg := &ChatMessage{}
			err = json.Unmarshal(result.Data, msg)
			if err == nil {
				analytics := &Analytics{}
				if msg.AnalyticsUUID != "" {
					anaBytes, lidAna := analyticsDB.Get(msg.AnalyticsUUID)
					if lidAna != "" {
						analyticsDB.Unlock(msg.AnalyticsUUID, lidAna)
						err = json.Unmarshal(anaBytes.Data, analytics)
						if err != nil {
							analytics = &Analytics{}
						}
					}
				}
				container := &ChatMessageContainer{
					ChatMessage: msg,
					Analytics:   analytics,
					UUID:        result.uUID,
				}
				messages.Messages[i] = container
			}
		}
		render.JSON(w, r, messages)
	}
}

func (db *GoDB) handleChatMessageDelete(chatServer *ChatServer, chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		msgID := chi.URLParam(r, "msgID")
		if msgID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get message
		resp, lid := db.Get(msgID)
		if lid == "" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		message := &ChatMessage{}
		err := json.Unmarshal(resp.Data, message)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		_, chatMember, chatGroup, _ := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			message.ChatGroupUUID, user.Username, password, r)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Is the user the author of this message?
		if message.Username != user.Username {
			// No... does the user have admin rights?
			usrRole := chatMember.GetRoleInformation(chatGroup.ChatGroup)
			if !usrRole.IsAdmin {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
		// Distribute action message (including sanitized chat message)
		message.Username = ""
		message.Text = ""
		message.TimeCreated = ""
		container := &ChatMessageContainer{
			ChatMessage: message,
			UUID:        resp.uUID,
		}
		actionMessage := &ChatActionMessage{
			ChatMessageContainer: container,
			Action:               "delete",
		}
		go chatServer.DistributeChatActionMessageJSON(actionMessage)
		// Delete message
		err = db.Delete(msgID, lid)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleChatMessageReaction(
	chatServer *ChatServer, chatGroupDB, chatMemberDB, analyticsDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		msgID := chi.URLParam(r, "msgID")
		if msgID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		chatID := r.URL.Query().Get("src")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &ChatMessageReaction{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Sanitize
		request.Reaction = strings.ToLower(request.Reaction)
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		chatGroup, chatMember, _, _ := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil, chatID, user.Username, password, r)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve message and check if there is an Analytics entry available
		messageBytes, lidMsg := db.Get(msgID)
		defer db.Unlock(msgID, lidMsg)
		if lidMsg == "" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		message := &ChatMessage{}
		err := json.Unmarshal(messageBytes.Data, message)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		var analytics *Analytics
		analyticsUpdate := false
		var analyticsBytes *EntryResponse
		lidAna := ""
		if message.AnalyticsUUID != "" {
			analyticsBytes, lidAna = analyticsDB.Get(message.AnalyticsUUID)
			defer analyticsDB.Unlock(message.AnalyticsUUID, lidAna)
			if lidAna != "" {
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
				Reactions: make(map[string][]string, 1),
				Downloads: 0,
				Bookmarks: 0,
			}
			analytics.Reactions[request.Reaction] = []string{user.Username}
		} else {
			// Check if reaction is present already, if yes -> remove (toggle functionality)
			index := -1
			rUsers, ok := analytics.Reactions[request.Reaction]
			if ok && len(rUsers) > 0 {
				for ix, rUser := range rUsers {
					if rUser == user.Username {
						// Found -> Remove
						index = ix
						break
					}
				}
				reactions := analytics.Reactions[request.Reaction]
				if index != -1 {
					// Delete
					reactions = append(reactions[:index], reactions[index+1:]...)
					reactionRemoved = true
				} else {
					// Append
					reactions = append(reactions, user.Username)
				}
				analytics.Reactions[request.Reaction] = reactions
			} else {
				// No reaction of this type existed yet
				analytics.Reactions[request.Reaction] = []string{user.Username}
			}
		}
		// Distribute action message
		actionMsg := &ChatMessage{}
		actionMsg.Username = user.Username // User that reacted
		actionMsg.Text = request.Reaction  // Reaction as msg
		actionMsg.TimeCreated = ""
		actionMsg.WasEdited = reactionRemoved // Edit=true if reaction existed before thus was removed
		actionMsg.ChatGroupUUID = chatID
		container := &ChatMessageContainer{
			ChatMessage: actionMsg,
			UUID:        messageBytes.uUID,
		}
		actionMessage := &ChatActionMessage{
			ChatMessageContainer: container,
			Action:               "react",
		}
		go chatServer.DistributeChatActionMessageJSON(actionMessage)
		// Save
		analyticsJson, err := json.Marshal(analytics)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Commit changes
		if analyticsUpdate && analyticsBytes != nil {
			// Analytics existed -> Update them
			err = analyticsDB.Update(analyticsBytes.uUID, analyticsJson, lidAna, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			// Insert analytics while returning its UUID to the message for reference
			message.AnalyticsUUID, err = analyticsDB.Insert(analyticsJson, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Update message
			messageJson, err := json.Marshal(message)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(messageBytes.uUID, messageJson, lidMsg, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
	}
}
