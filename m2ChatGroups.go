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
	"strings"
)

type ChatUserRoleModification struct {
	Username string `json:"usr"`
	Role     string `json:"role"`
}

type ChatRole struct {
	Name     string  `json:"t"`
	Index    float64 `json:"index"`
	ColorHex string  `json:"hex"`
	IsAdmin  bool    `json:"admin"`
}

type SubChatroom struct {
	UUID        string
	Name        string
	Description string
}

type ChatGroupEntry struct {
	*ChatGroup
	UUID string
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
	ParentUUID           string        `json:"pid"`
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
	r.Route("/chat/private", func(r chi.Router) {
		// Creation and Retrieval
		r.Post("/create", db.handleChatGroupCreate(userDB, chatMemberDB))
		r.Get("/get/{chatID}", db.handleChatGroupGet())
		// Roles
		r.Post("/roles/mod/{chatID}", db.handleChatGroupRoleModification())
		// Users
		r.Route("/users", func(r chi.Router) {
			r.Post("/roles/mod/{chatID}", db.handleChatMemberRoleModification(chatMemberDB))
			r.Get("/members/{chatID}", db.handleChatGroupGetMembers(chatMemberDB))
		},
		)
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
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
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
					IsAdmin:  true,
				},
				ChatRole{
					Name:     "member",
					Index:    40_000,
					ColorHex: "",
					IsAdmin:  false,
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

func (a *ChatRole) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	return nil
}

func (a *ChatUserRoleModification) Bind(_ *http.Request) error {
	if a.Username == "" {
		return errors.New("missing username")
	}
	if a.Role == "" {
		return errors.New("missing role")
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
		response, ok := db.Get(chatID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		chatGroup := &ChatGroup{}
		err := json.Unmarshal(response.Data, chatGroup)
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
	chatGroupDB, chatMemberDB *GoDB, chatID, username, password string) (
	*ChatGroupEntry, *ChatMemberEntry, *ChatGroupEntry, error,
) {
	// Check if chat group exists
	dataOriginal, ok := chatGroupDB.Get(chatID)
	if !ok {
		return nil, nil, nil, nil
	}
	// Retrieve chat group from database
	chatGroupOriginal := &ChatGroup{}
	err := json.Unmarshal(
		dataOriginal.Data,
		chatGroupOriginal,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	chatGroup := *chatGroupOriginal
	// Is this a sub chat group? If so, then retrieve the main chat group
	var chatGroupMain *ChatGroup
	var dataMain *EntryResponse
	if chatGroupOriginal.ParentUUID != "" {
		chatID = chatGroupOriginal.ParentUUID
		dataMain, ok = chatGroupDB.Get(chatID)
		if !ok {
			return nil, nil, nil, nil
		}
		// Retrieve chat group from database
		chatGroupMain = &ChatGroup{}
		err = json.Unmarshal(
			dataMain.Data,
			chatGroupMain,
		)
		if err != nil {
			chatGroupMain = nil
		}
	} else {
		chatGroupMain = nil
	}
	// Retrieve chat member
	query := fmt.Sprintf(
		"^%s-%s$",
		chatID,
		username,
	)
	// MaxResults 1 to have maximum performance (it avoids unnecessary searching)
	options := &SelectOptions{
		MaxResults: 1,
		Page:       0,
		Skip:       0,
	}
	resp, err := chatMemberDB.Select(
		map[string]string{
			"chat-user": query,
		}, options,
	)
	if err != nil {
		return nil, nil, nil, err
	}
	responseMember := <-resp
	var chatMember *ChatMember
	if len(responseMember) < 1 {
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
			responseMember[0].Data,
			chatMember,
		)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	chatGroupEntry := &ChatGroupEntry{
		ChatGroup: chatGroupOriginal,
		UUID:      dataOriginal.uUID,
	}
	var chatGroupMainEntry *ChatGroupEntry
	if chatGroupMain != nil {
		chatGroupMainEntry = &ChatGroupEntry{
			ChatGroup: chatGroupMain,
			UUID:      dataMain.uUID,
		}
	} else {
		chatGroupMainEntry = nil
	}
	chatMemberEntry := &ChatMemberEntry{
		ChatMember: chatMember,
		UUID:       responseMember[0].uUID,
	}
	return chatGroupEntry, chatMemberEntry, chatGroupMainEntry, nil
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

func (db *GoDB) handleChatGroupRoleModification() http.HandlerFunc {
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
		// TODO: Check if calling user is member and has at least one admin role
		// Check if the role should be deleted
		doDeleteTmp := r.URL.Query().Get("del")
		doDelete := false
		if doDeleteTmp != "" {
			if doDeleteTmp == "true" {
				doDelete = true
			}
		}
		// Retrieve POST payload
		request := &ChatRole{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Validate and sanitize
		request.Name = strings.ToLower(request.Name)
		if request.Name == "owner" || request.Name == "member" || request.Name == "_server" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve chat group
		response, ok := db.Get(chatID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		chatGroup := &ChatGroup{}
		err := json.Unmarshal(response.Data, chatGroup)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if role is present
		index := -1
		for ix, role := range chatGroup.Roles {
			if role.Name == request.Name {
				index = ix
				break
			}
		}
		if doDelete && index == -1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		if doDelete {
			chatGroup.Roles = append(chatGroup.Roles[:index], chatGroup.Roles[index+1:]...)
		} else {
			if request.Index < 1.0 {
				if request.IsAdmin {
					request.Index = 30_000
				} else {
					request.Index = 40_000
				}
			}
			// Did it exist yet?
			if index == -1 {
				chatGroup.Roles = append(chatGroup.Roles, *request)
			} else {
				chatGroup.Roles[index] = *request
			}
		}
		jsonEntry, err := json.Marshal(chatGroup)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(response.uUID, jsonEntry, map[string]string{})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}
func (db *GoDB) handleChatMemberRoleModification(chatMemberDB *GoDB) http.HandlerFunc {
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
		// TODO: Check if calling user is member and has at least one role higher than the user about to be modified
		// Check if the role should be deleted
		doDeleteTmp := r.URL.Query().Get("del")
		doDelete := false
		if doDeleteTmp != "" {
			if doDeleteTmp == "true" {
				doDelete = true
			}
		}
		// Retrieve POST payload
		request := &ChatUserRoleModification{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve chat group etc.
		_, chatMember, _, err := GetChatGroupAndMember(db, chatMemberDB, chatID, request.Username, "")
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if role is present
		index := -1
		for ix, role := range chatMember.Roles {
			if role == request.Role {
				index = ix
				break
			}
		}
		if doDelete && index == -1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		if doDelete {
			chatMember.Roles = append(chatMember.Roles[:index], chatMember.Roles[index+1:]...)
		} else {
			// Did it exist yet?
			if index == -1 {
				chatMember.Roles = append(chatMember.Roles, request.Role)
			} else {
				chatMember.Roles[index] = request.Role
			}
		}
		jsonEntry, err := json.Marshal(chatMember)
		err = chatMemberDB.Update(chatMember.UUID, jsonEntry, map[string]string{
			"chat-user": fmt.Sprintf("%s-%s", chatID, chatMember.Username)},
		)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleChatGroupGetMembers(chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chatID := chi.URLParam(r, "chatID")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve chat member
		query := fmt.Sprintf("^%s-.*$", chatID)
		resp, err := chatMemberDB.Select(
			map[string]string{
				"chat-user": query,
			}, nil,
		)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		responseMember := <-resp
		if len(responseMember) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		members := ChatMemberList{
			ChatMembers: make([]*ChatMember, len(responseMember)),
		}
		for i, entry := range responseMember {
			chatMember := &ChatMember{}
			err = json.Unmarshal(entry.Data, chatMember)
			if err == nil {
				members.ChatMembers[i] = chatMember
			}
		}
		if len(members.ChatMembers) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		render.JSON(w, r, members)
	}
}
