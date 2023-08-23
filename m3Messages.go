package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
)

type ChatMessage struct {
	ChatGroupUUID string `json:"pid"`
	Text          string `json:"msg"`
	Username      string `json:"usr"`
	TimeCreated   string `json:"ts"`
	WasEdited     bool   `json:"e"`
	AnalyticsUUID string `json:"ana"` // Views, likes etc. will be stored in a separate database
}

type ChatMessageContainer struct {
	*ChatMessage
	UUID string
}

type ChatActionMessage struct {
	*ChatMessageContainer
	action string
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
	r chi.Router, tokenAuth *jwtauth.JWTAuth, chatServer *ChatServer, chatGroupDB, chatMemberDB *GoDB,
) {
	r.Route(
		"/msg/private", func(r chi.Router) {
			r.Post("/create", db.handleChatMessageCreate(chatServer, chatGroupDB, chatMemberDB))
			r.Post("/edit/{msgID}", db.handleChatMessageEdit(chatServer, chatGroupDB, chatMemberDB))
			r.Get("/delete/{msgID}", db.handleChatMessageDelete(chatServer, chatGroupDB, chatMemberDB))
			r.Route("/chat", func(r chi.Router) {
				r.Get("/get/{chatID}", db.handleChatMessageFromChat(chatServer, chatGroupDB, chatMemberDB))
			},
			)
		},
	)
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
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		chatGroup, chatMember, _, _ := GetChatGroupAndMember(
			chatGroupDB, chatMemberDB, request.ChatGroupUUID, user.Username, password,
		)
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
		// Distribute message
		go chatServer.DistributeChatMessageJSON(request)
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
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		chatGroup, chatMember, _, _ := GetChatGroupAndMember(
			chatGroupDB, chatMemberDB, request.ChatGroupUUID, user.Username, password,
		)
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
			action:               "edit",
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
			request.UUID, jsonMessage, map[string]string{
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

func (db *GoDB) handleChatMessageFromChat(chatServer *ChatServer, chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
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
		chatGroup, chatMember, _, err := GetChatGroupAndMember(
			chatGroupDB, chatMemberDB, chatID, user.Username, password,
		)
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
		// Retrieve messages from this chat group
		resp, err := db.Select(map[string]string{
			"chatID": chatID,
		}, options)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		if len(response) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		messages := make([]*ChatMessageContainer, len(response))
		for i, result := range response {
			msg := &ChatMessage{}
			err = json.Unmarshal(result.Data, msg)
			if err == nil {
				container := &ChatMessageContainer{
					ChatMessage: msg,
					UUID:        result.uUID,
				}
				messages[i] = container
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
		resp, ok := db.Get(msgID)
		if !ok {
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
		chatGroup, chatMember, _, _ := GetChatGroupAndMember(
			chatGroupDB, chatMemberDB, message.ChatGroupUUID, user.Username, password,
		)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
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
			action:               "delete",
		}
		go chatServer.DistributeChatActionMessageJSON(actionMessage)
		// Delete message
	}
}
