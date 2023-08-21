package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
)

type ChatRole struct {
	Name     string  `json:"t"`
	Index    float32 `json:"index"`
	ColorHex string  `json:"hex"`
}

type SubChatroom struct {
	UUID        string
	Name        string
	Description string
}

type ChatGroup struct {
	Name                 string        `json:"t"`
	Description          string        `json:"desc"`
	TimeCreated          string        `json:"ts"`
	RulesRead            []string      `json:"rrules"`
	RulesWrite           []string      `json:"wrules"`
	Roles                []ChatRole    `json:"roles"`
	IsPrivate            bool          `json:"priv"`
	Password             string        `json:"pw"`
	Subchatrooms         []SubChatroom `json:"subc"`
	ParentUUID           string        `json:"parent"`
	ThumbnailURL         string        `json:"iurl"`
	ThumbnailAnimatedURL string        `json:"iurla"`
	BannerURL            string        `json:"burl"`
	BannerAnimatedURL    string        `json:"burla"`
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
		if request.Roles == nil {
			request.Roles = make([]ChatRole, 0)
			request.Roles = append(request.Roles,
				ChatRole{
					Name:     "owner",
					Index:    20_000,
					ColorHex: "",
				},
				ChatRole{
					Name:     "member",
					Index:    40_000,
					ColorHex: "",
				})
		}
		if request.Subchatrooms == nil {
			request.Subchatrooms = make([]SubChatroom, 0)
		}
		if request.RulesWrite == nil {
			request.RulesWrite = make([]string, 0)
			request.RulesWrite = append(request.RulesWrite, "member")
		}
		if request.RulesRead == nil {
			request.RulesRead = make([]string, 0)
			request.RulesRead = append(request.RulesRead, "member")
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

func GetChatGroupAndMember(
	chatGroupDB, chatMemberDB *GoDB, chatID, username, password string) (*ChatGroup, *ChatMember, *ChatGroup, error,
) {
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
		return nil, nil, nil, err
	}
	response := <-resp
	if len(response) < 1 {
		return nil, nil, nil, err
	}
	// Retrieve chat group from database
	chatGroupOriginal := &ChatGroup{}
	err = json.Unmarshal(
		response[0].Data,
		chatGroupOriginal,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	chatGroup := *chatGroupOriginal
	// Is this a sub chat group? If so, then retrieve the main chat group
	var chatGroupMain *ChatGroup
	if chatGroupOriginal.ParentUUID != "" {
		chatID = chatGroupOriginal.ParentUUID
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
			return nil, nil, nil, err
		}
		response = <-resp
		if len(response) < 1 {
			return nil, nil, nil, err
		}
		// Retrieve chat group from database
		chatGroupMain = &ChatGroup{}
		err = json.Unmarshal(
			response[0].Data,
			chatGroupMain,
		)
		if err != nil {
			return nil, nil, nil, err
		}
		chatGroup = *chatGroupMain
	} else {
		chatGroupMain = nil
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
		return nil, nil, nil, err
	}
	response = <-resp
	var chatMember *ChatMember
	if len(response) < 1 {
		// No user was found -> Is the chat group private? If not, join
		if chatGroup.IsPrivate {
			isMatch := subtle.ConstantTimeCompare(
				[]byte(password),
				[]byte(chatGroup.Password),
			)
			if isMatch != 1 {
				return nil, nil, nil, err
			}
		}
		chatMember = &ChatMember{
			Username:             username,
			ChatGroupUUID:        chatID,
			DisplayName:          username,
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
					username,
				),
			},
		)
		if err != nil {
			return nil, nil, nil, err
		}
	} else {
		// Retrieve user from database
		chatMember = &ChatMember{}
		err = json.Unmarshal(
			response[0].Data,
			chatMember,
		)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	return chatGroupOriginal, chatMember, chatGroupMain, nil
}

func CheckWriteRights(user *ChatMember, chatGroup *ChatGroup) bool {
	hasRight := false
	for _, role := range chatGroup.RulesWrite {
		for _, usrRole := range user.Roles {
			if usrRole == role {
				hasRight = true
				break
			}
		}
		if hasRight {
			break
		}
	}
	return hasRight
}

func CheckReadRights(user *ChatMember, chatGroup *ChatGroup) bool {
	hasRight := false
	for _, role := range chatGroup.RulesRead {
		for _, usrRole := range user.Roles {
			if usrRole == role {
				hasRight = true
				break
			}
		}
		if hasRight {
			break
		}
	}
	return hasRight
}
