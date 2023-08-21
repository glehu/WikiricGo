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

type ChatGroup struct {
	Name                 string        `json:"t"`
	Description          string        `json:"desc"`
	TimeCreated          string        `json:"ts"`
	RulesRead            []string      `json:"rrules"`
	RulesWrite           []string      `json:"wrules"`
	IsPrivate            bool          `json:"priv"`
	Password             string        `json:"pw"`
	Subchatrooms         []SubChatroom `json:"subc"`
	ParentUUID           string        `json:"parent"`
	ThumbnailURL         string        `json:"iurl"`
	ThumbnailAnimatedURL string        `json:"iurla"`
	BannerURL            string        `json:"burl"`
	BannerAnimatedURL    string        `json:"burla"`
}

type SubChatroom struct {
	UUID        string
	Name        string
	Description string
}

func OpenChatGroupDatabase() *GoDB {
	db := OpenDB("chatGroups", []string{})
	return db
}

func (db *GoDB) ProtectedChatGroupEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth, userDB, chatMemberDB *GoDB) {
	r.Route(
		"/chat/private", func(r chi.Router) {
			r.Post("/create", db.handleChatGroupCreate(userDB, chatMemberDB))
			r.Get("/get/{chatID}", db.handleChatGroupGet())
		},
	)
}

func (db *GoDB) handleChatGroupCreate(userDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &ChatGroup{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Initialize chat group
		if request.Subchatrooms == nil {
			request.Subchatrooms = make([]SubChatroom, 0)
		}
		request.TimeCreated = TimeNowIsoString()
		if request.Password == "" {
			request.IsPrivate = false
		}
		length := len(request.Name)
		if length > 50 {
			length = 50
		}
		request.Name = request.Name[0:length]
		if request.Description != "" {
			length = len(request.Description)
			if length > 500 {
				length = 500
			}
			request.Description = request.Description[0:length]
		}
		// Save it
		newChatGroup, err := json.Marshal(request)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(newChatGroup, map[string]string{})
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
		// Now add the chat member
		chatMember := &ChatMember{
			Username:             user.Username,
			ChatGroupUUID:        uUID,
			DisplayName:          user.DisplayName,
			Roles:                []string{"owner", "member"},
			PublicKey:            "",
			ThumbnailURL:         "",
			ThumbnailAnimatedURL: "",
			BannerURL:            "",
			BannerAnimatedURL:    "",
		}
		newMember, err := json.Marshal(chatMember)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, err = chatMemberDB.Insert(
			newMember, map[string]string{
				"chat-user": fmt.Sprintf("%s-%s", uUID, user.Username),
			},
		)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (a *ChatGroup) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	return nil
}

func (db *GoDB) handleChatGroupGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chatID := chi.URLParam(r, "chatID")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		query := fmt.Sprintf("^%s$", chatID)
		resp, err := db.Select(
			map[string]string{
				"uuid": query,
			},
		)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		if len(response) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		chatGroup := &ChatGroup{}
		err = json.Unmarshal(response[0].Data, chatGroup)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Sanitize
		chatGroup.Password = ""
		render.JSON(w, r, chatGroup)
	}
}
