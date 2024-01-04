package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
	"strings"
)

const GroupDB = "m2"

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
	UUID        string `json:"uid"`
	Name        string `json:"t"`
	Description string `json:"desc"`
	Type        string `json:"type"`
}

type ChatGroupEntry struct {
	*ChatGroup
	UUID string `json:"uid"`
}

type ChatGroup struct {
	Name                 string        `json:"t"`
	Type                 string        `json:"type"`
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
	IsEncrypted          bool          `json:"crypt"`
	IsCommunity          bool          `json:"iscom"`
}

type FriendList struct {
	Friends []*FriendGroup `json:"friends"`
}

type FriendGroup struct {
	*ChatMemberEntry `json:"friend"`
	*ChatGroupEntry  `json:"chat"`
	*ChatMessage     `json:"msg"`
}

type PublicKeyRequest struct {
	PubKeyPEM string `json:"pubKeyPEM"`
}

type ActiveUsersResponse struct {
	ActiveUsers []string `json:"active"`
}

type ChatGroupModification struct {
	Type     string `json:"type"`
	Field    string `json:"field"`
	OldValue string `json:"old"`
	NewValue string `json:"new"`
}

type ChatMemberModification struct {
	Type     string `json:"type"`
	Field    string `json:"field"`
	OldValue string `json:"old"`
	NewValue string `json:"new"`
}

func (db *GoDB) ProtectedChatGroupEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	rapidDB *GoDB, chatServer *ChatServer,
) {
	r.Route("/chat/private", func(r chi.Router) {
		// Creation and Retrieval
		r.Post("/create", db.handleChatGroupCreate())
		r.Post("/mod/{chatID}", db.handleChatGroupModification(rapidDB))
		r.Get("/get/{chatID}", db.handleChatGroupGet())
		// Roles
		r.Post("/roles/mod/{chatID}", db.handleChatGroupRoleModification())
		// PubKey
		r.Post("/pubkey/{chatID}", db.handlePublicKeySet())
		// Users
		r.Route("/users", func(r chi.Router) {
			r.Post("/roles/mod/{chatID}", db.handleChatMemberRoleModification())
			r.Get("/members/{chatID}", db.handleChatGroupGetMembers())
			r.Get("/friends", db.handleGetFriends(rapidDB))
			r.Get("/active/{chatID}", db.handleChatGroupGetActiveMembers(chatServer))
		})
		// Self Actions
		r.Route("/self", func(r chi.Router) {
			r.Post("/mod/{chatID}", db.handleChatMemberModification(rapidDB))
		})
	})
}

func (db *GoDB) handleChatGroupCreate() http.HandlerFunc {
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request.TimeCreated = TimeNowIsoString()
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
		// Is this a community?
		if request.IsCommunity == true {
			// Communities are not encrypted to make thousands of members possible!
			request.IsEncrypted = false
		} else {
			// Encrypt non-community chat groups
			request.IsEncrypted = true
		}
		// Save it
		newChatGroup, err := json.Marshal(request)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(GroupDB, newChatGroup, map[string]string{})
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
		// Check if we need to update a parent chat group
		if request.ParentUUID != "" {
			// Retrieve parent chat group
			response, txn := db.Get(GroupDB, request.ParentUUID)
			if txn == nil {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			defer txn.Discard()
			chatGroup := &ChatGroup{}
			err = json.Unmarshal(response.Data, chatGroup)
			if err != nil {
				fmt.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			chatGroup.Subchatrooms = append(chatGroup.Subchatrooms, SubChatroom{
				UUID:        uUID,
				Name:        request.Name,
				Description: request.Description,
				Type:        request.Type,
			})
			chatGroupJson, err := json.Marshal(chatGroup)
			if err != nil {
				fmt.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(GroupDB, txn, response.uUID, chatGroupJson, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			// Add the chat member (main chatroom only!)
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
				DateCreated:          TimeNowIsoString(),
			}
			newMember, err := json.Marshal(chatMember)
			if err != nil {
				fmt.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			_, err = db.Insert(MemberDB,
				newMember, map[string]string{
					"chat-usr": fmt.Sprintf("%s;%s;", uUID, user.Username),
				},
			)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
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

func (p PublicKeyRequest) Bind(r *http.Request) error {
	if p.PubKeyPEM == "" {
		return errors.New("missing pubkey")
	}
	return nil
}

func (a *ChatGroupModification) Bind(_ *http.Request) error {
	if a.Type == "" {
		return errors.New("missing type")
	}
	if a.Field == "" {
		return errors.New("missing field")
	}
	return nil
}

func (a *ChatMemberModification) Bind(_ *http.Request) error {
	if a.Type == "" {
		return errors.New("missing type")
	}
	if a.Field == "" {
		return errors.New("missing field")
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
		chatGroup, err := db.ReadChatGroup(chatID)
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

func (db *GoDB) ReadChatGroup(chatID string) (*ChatGroupEntry, error) {
	response, ok := db.Read(GroupDB, chatID)
	if !ok {
		return nil, errors.New("no chat group found")
	}
	chatGroup := &ChatGroup{}
	err := json.Unmarshal(response.Data, chatGroup)
	if err != nil {
		return nil, err
	}
	entry := &ChatGroupEntry{
		ChatGroup: chatGroup,
		UUID:      response.uUID,
	}
	return entry, err
}

func GetChatMember(mainDB *GoDB, chatID, username string) (*ChatMemberEntry, *badger.Txn) {
	// Check if chat group exists
	dataOriginal, ok := mainDB.Read(GroupDB, chatID)
	if !ok {
		return nil, nil
	}
	// Retrieve chat group from database
	chatGroupOriginal := &ChatGroup{}
	err := json.Unmarshal(
		dataOriginal.Data,
		chatGroupOriginal,
	)
	if err != nil {
		return nil, nil
	}
	// Is this a sub chat group? If so, then retrieve the main chat group
	var chatGroupMain *ChatGroup
	var dataMain *EntryResponse
	if chatGroupOriginal.ParentUUID != "" {
		// Get parent
		chatID = chatGroupOriginal.ParentUUID
		dataMain, ok = mainDB.Read(GroupDB, chatID)
		if !ok {
			return nil, nil
		}
		// Retrieve chat group from database
		chatGroupMain = &ChatGroup{}
		err = json.Unmarshal(
			dataMain.Data,
			chatGroupMain,
		)
		if err != nil {
			return nil, nil
		}
	} else {
		// Chat has no parent so we'll take the original
		chatGroupMain = chatGroupOriginal
	}
	// Retrieve chat member
	query := fmt.Sprintf(
		"%s;%s;",
		chatID,
		username,
	)
	// MaxResults 1 to have maximum performance (it avoids unnecessary searching)
	resp, err := mainDB.Select(MemberDB,
		map[string]string{
			"chat-usr": query,
		}, &SelectOptions{
			MaxResults: 1,
			Page:       0,
			Skip:       0,
		},
	)
	if err != nil {
		return nil, nil
	}
	responseMember := <-resp
	if len(responseMember) < 1 {
		return nil, nil
	}
	var chatMember *ChatMember
	// Retrieve user from database
	chatMember = &ChatMember{}
	err = json.Unmarshal(
		responseMember[0].Data,
		chatMember,
	)
	if err != nil {
		return nil, nil
	}
	// Lock it
	_, txn := mainDB.Get(MemberDB, responseMember[0].uUID)
	entry := &ChatMemberEntry{
		ChatMember: chatMember,
		UUID:       responseMember[0].uUID,
	}
	return entry, txn
}

func ReadChatGroupAndMember(
	mainDB, rapidDB *GoDB,
	connector *Connector,
	chatID, username, password string,
	r *http.Request) (
	*ChatGroupEntry, *ChatMemberEntry, *ChatGroupEntry, error,
) {
	user := r.Context().Value("user").(*User)
	if user == nil {
		return nil, nil, nil, errors.New("no user provided")
	}
	// Check if chat group exists
	dataOriginal, ok := mainDB.Read(GroupDB, chatID)
	if !ok {
		return nil, nil, nil, errors.New("err chat group nonexistent")
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
		// Get parent
		chatID = chatGroupOriginal.ParentUUID
		dataMain, ok = mainDB.Read(GroupDB, chatID)
		if !ok {
			return nil, nil, nil, errors.New("err provided main chat group nonexistent")
		}
		// Retrieve chat group from database
		chatGroupMain = &ChatGroup{}
		err = json.Unmarshal(
			dataMain.Data,
			chatGroupMain,
		)
		if err != nil {
			return nil, nil, nil, errors.New("err loading main chat group")
		}
	} else {
		// Chat has no parent so we'll take the original
		chatGroupMain = chatGroupOriginal
	}
	// Retrieve chat member
	query := fmt.Sprintf(
		"%s;%s;",
		chatID,
		username,
	)
	// MaxResults 1 to have maximum performance (it avoids unnecessary searching)
	resp, err := mainDB.Select(MemberDB,
		map[string]string{
			"chat-usr": query,
		}, &SelectOptions{
			MaxResults: 1,
			Page:       0,
			Skip:       0,
		},
	)
	if err != nil {
		return nil, nil, nil, err
	}
	responseMember := <-resp
	var chatMember *ChatMember
	var memberUUID string
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
		// Are we joining a DM group? If so, then we'll give the owner rule, too
		// We also need to notify the other member (this is how friend request work)
		var roles []string
		var indices map[string]string
		if chatGroup.Type == "dm" {
			// Check if a password was provided in the url query
			refUsername := r.URL.Query().Get("ref")
			if refUsername != "" {
				// DM group
				roles = []string{"owner", "member"}
				indices = map[string]string{
					"chat-usr":    fmt.Sprintf("%s;%s;", chatID, username),
					"user-friend": fmt.Sprintf("%s;%s;", refUsername, username), // Sides switched to enable friend query
				}
				go func() {
					err = notifyFriendRequestAccept(refUsername, user, rapidDB, connector, chatID, password)
					if err != nil {
						fmt.Println(err)
						return
					}
				}()
			} else {
				roles = []string{"member"}
			}
		} else {
			// No DM group
			roles = []string{"member"}
			indices = map[string]string{
				"chat-usr": fmt.Sprintf("%s;%s;", chatID, username),
			}
			go func() {
				container := &ChatGroupEntry{
					ChatGroup: &chatGroup,
					UUID:      dataOriginal.uUID,
				}
				err = notifyJoin(user.DisplayName, mainDB, rapidDB, connector, container)
				if err != nil {
					fmt.Println(err)
					return
				}
			}()
		}
		chatMember = &ChatMember{
			Username:             user.Username,
			ChatGroupUUID:        chatID,
			DisplayName:          user.DisplayName,
			Roles:                roles,
			PublicKey:            "", // Public Key will be submitted by the client
			ThumbnailURL:         "",
			ThumbnailAnimatedURL: "",
			BannerURL:            "",
			BannerAnimatedURL:    "",
			DateCreated:          TimeNowIsoString(),
		}
		newMember, err := json.Marshal(chatMember)
		memberUUID, err = mainDB.Insert(MemberDB, newMember, indices)
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
		memberUUID = responseMember[0].uUID
	}
	chatGroupEntry := &ChatGroupEntry{
		ChatGroup: chatGroupOriginal,
		UUID:      dataOriginal.uUID,
	}
	var chatGroupMainEntry *ChatGroupEntry
	if dataMain != nil {
		chatGroupMainEntry = &ChatGroupEntry{
			ChatGroup: chatGroupMain,
			UUID:      dataMain.uUID,
		}
	} else {
		chatGroupMainEntry = &ChatGroupEntry{
			ChatGroup: chatGroupOriginal,
			UUID:      dataOriginal.uUID,
		}
	}
	chatMemberEntry := &ChatMemberEntry{
		ChatMember: chatMember,
		UUID:       memberUUID,
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Validate and sanitize
		request.Name = strings.ToLower(request.Name)
		if request.Name == "owner" || request.Name == "member" || request.Name == "_server" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve chat group
		response, txn := db.Get(GroupDB, chatID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
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
		err = db.Update(GroupDB, txn, response.uUID, jsonEntry, map[string]string{})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleChatMemberRoleModification() http.HandlerFunc {
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve chat group etc.
		_, chatMember, _, err := ReadChatGroupAndMember(
			db, nil, nil, chatID, request.Username, "", r)
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
		_, txn := db.Get(MemberDB, chatMember.UUID)
		defer txn.Discard()
		jsonEntry, err := json.Marshal(chatMember)
		err = db.Update(MemberDB, txn, chatMember.UUID, jsonEntry, map[string]string{
			"chat-usr": fmt.Sprintf("%s;%s;", chatID, chatMember.Username)},
		)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleChatGroupGetMembers() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		chatID := chi.URLParam(r, "chatID")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Check if we're targeting a sub chat since only main chat rooms have members technically
		dataOriginal, ok := db.Read(GroupDB, chatID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		// Retrieve chat group from database
		chatGroupOriginal := &ChatGroup{}
		err := json.Unmarshal(
			dataOriginal.Data,
			chatGroupOriginal,
		)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		if chatGroupOriginal.ParentUUID != "" {
			// Change chatID to parent
			chatID = chatGroupOriginal.ParentUUID
		}
		// Retrieve chat members
		query := FIndex(chatID)
		resp, err := db.Select(MemberDB,
			map[string]string{
				"chat-usr": query,
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

func notifyFriendRequestAccept(refUsername string, user *User,
	rapidDB *GoDB, connector *Connector, chatID, password string,
) error {
	if rapidDB == nil {
		return nil
	}
	notification := &Notification{
		Title:             "Friend Request Accepted",
		Description:       fmt.Sprintf("%s accepted your friend request!", user.DisplayName),
		Type:              "frequest",
		TimeCreated:       TimeNowIsoString(),
		RecipientUsername: refUsername,
		ClickAction:       "join",
		ClickModule:       "chat",
		ClickUUID:         fmt.Sprintf("%s?pw=%s&ref=%s", chatID, password, user.Username),
	}
	jsonNotification, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	notificationUUID, err := rapidDB.Insert(NotifyDB, jsonNotification, map[string]string{
		"usr": FIndex(refUsername),
	})
	if err != nil {
		return err
	}
	// Now send a message via the connector
	connector.SessionsMu.RLock()
	defer connector.SessionsMu.RUnlock()
	session, ok := connector.Sessions.Get(refUsername)
	if !ok {
		return nil
	}
	cMSG := &ConnectorMsg{
		Type:          "[s:NOTIFICATION]",
		Action:        "frequest",
		ReferenceUUID: notificationUUID,
		Username:      user.DisplayName,
		Message:       fmt.Sprintf("%s accepted your friend request!", user.DisplayName),
	}
	_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	return nil
}

func notifyJoin(selfName string, mainDB, rapidDB *GoDB, connector *Connector, chatGroup *ChatGroupEntry,
) error {
	if rapidDB == nil {
		return nil
	}
	// Retrieve all members of this chat group
	query := FIndex(chatGroup.UUID)
	resp, err := mainDB.Select(MemberDB, map[string]string{"chat-usr": query}, nil)
	if err != nil {
		return err
	}
	responseMember := <-resp
	if len(responseMember) < 1 {
		return nil
	}
	// Send a notification for each admin
	for _, entry := range responseMember {
		chatMember := &ChatMember{}
		err = json.Unmarshal(entry.Data, chatMember)
		if err == nil {
			continue
		}
		userRole := chatMember.GetRoleInformation(chatGroup.ChatGroup)
		if !userRole.IsAdmin {
			continue
		}
		notification := &Notification{
			Title:             "New Member",
			Description:       fmt.Sprintf("%s has joined %s!", selfName, chatGroup.Name),
			Type:              "info",
			TimeCreated:       TimeNowIsoString(),
			RecipientUsername: chatMember.Username,
			ClickAction:       "join",
			ClickModule:       "chat",
			ClickUUID:         fmt.Sprintf("%s", chatGroup.UUID),
		}
		jsonNotification, err := json.Marshal(notification)
		if err != nil {
			continue
		}
		notificationUUID, err := rapidDB.Insert(NotifyDB, jsonNotification, map[string]string{
			"usr": FIndex(chatMember.Username),
		})
		if err != nil {
			continue
		}
		// Now send a message via the connector
		connector.SessionsMu.RLock()
		session, ok := connector.Sessions.Get(chatMember.Username)
		if !ok {
			connector.SessionsMu.RUnlock()
			continue
		}
		cMSG := &ConnectorMsg{
			Type:          "[s:NOTIFICATION]",
			Action:        "info",
			ReferenceUUID: notificationUUID,
			Username:      selfName,
			Message:       fmt.Sprintf("%s has joined %s!", selfName, chatGroup.Name),
		}
		_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
		connector.SessionsMu.RUnlock()
	}
	return nil
}

func (db *GoDB) handleGetFriends(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve friends
		members := FriendList{
			Friends: make([]*FriendGroup, 0),
		}
		resp, err := db.Select(MemberDB, map[string]string{
			"user-friend": FIndex(user.Username),
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		responseMember := <-resp
		if len(responseMember) < 1 {
			render.JSON(w, r, members)
			return
		}
		for _, entry := range responseMember {
			chatMember := &ChatMember{}
			err = json.Unmarshal(entry.Data, chatMember)
			if err == nil {
				chatGroup, err := db.ReadChatGroup(chatMember.ChatGroupUUID)
				if err != nil {
					fmt.Println(err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				// Retrieve last message sent
				msgResp, err := rapidDB.Select(MessageDB, map[string]string{
					"chatID": chatMember.ChatGroupUUID,
				}, &SelectOptions{
					MaxResults: 1,
					Page:       0,
					Skip:       0,
				})
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				msgResponse := <-msgResp
				var lastMessage *ChatMessage
				if len(msgResponse) > 0 {
					lastMessage = &ChatMessage{}
					err = json.Unmarshal(msgResponse[0].Data, lastMessage)
					if err != nil {
						lastMessage = nil
					}
				}
				// Sanitize
				chatGroup.Password = ""
				members.Friends = append(members.Friends, &FriendGroup{
					ChatMemberEntry: &ChatMemberEntry{
						ChatMember: chatMember,
						UUID:       entry.uUID,
					},
					ChatGroupEntry: chatGroup,
					ChatMessage:    lastMessage,
				})
			}
		}
		if len(members.Friends) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		render.JSON(w, r, members)
	}
}

func (db *GoDB) handlePublicKeySet() http.HandlerFunc {
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
		// Check if chat group is encrypted before applying pubkey
		resp, ok := db.Read(GroupDB, chatID)
		if !ok {
			return
		}
		// Retrieve chat group from database
		chatGroup := &ChatGroup{}
		err := json.Unmarshal(
			resp.Data,
			chatGroup,
		)
		if err != nil {
			return
		}
		if chatGroup.IsEncrypted == false {
			return
		}
		// Retrieve POST payload
		request := &PublicKeyRequest{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve chat group etc.
		chatMember, txn := GetChatMember(db, chatID, user.Username)
		if chatMember == nil || txn == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		defer txn.Discard()
		// Check if member has a public key already
		if chatMember.PublicKey != "" {
			// Key exists -> Check if we're forcing an update
			doForce := r.URL.Query().Get("force")
			if doForce != "true" {
				// Exit if update is not forced
				return
			}
		}
		// Update PubKey
		chatMember.PublicKey = request.PubKeyPEM
		// Commit changes
		jsonEntry, err := json.Marshal(chatMember)
		err = db.Update(MemberDB, txn, chatMember.UUID, jsonEntry, map[string]string{
			"chat-usr": fmt.Sprintf("%s;%s;", chatID, chatMember.Username)},
		)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleChatGroupGetActiveMembers(chatServer *ChatServer) http.HandlerFunc {
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
		activeUsers := &ActiveUsersResponse{ActiveUsers: make([]string, 0)}
		chatServer.ChatGroupsMu.RLock()
		defer chatServer.ChatGroupsMu.RUnlock()
		sessions, ok := chatServer.ChatGroups.Get(chatID)
		if !ok {
			render.JSON(w, r, activeUsers)
			return
		}
		for _, s := range sessions {
			activeUsers.ActiveUsers = append(activeUsers.ActiveUsers, s.ChatMember.Username)
		}
		render.JSON(w, r, activeUsers)
	}
}

func (db *GoDB) handleChatGroupModification(rapidDB *GoDB) http.HandlerFunc {
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
		// Retrieve POST payload
		request := &ChatGroupModification{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check what action is required
		var err error
		if request.Type == "edit" {
			if request.Field == "iurl" {
				err = db.changeChatGroupImage(rapidDB, user, chatID, request, false, false)
			} else if request.Field == "burl" {
				err = db.changeChatGroupImage(rapidDB, user, chatID, request, true, false)
			} else if request.Field == "pw" {
				err = db.changeChatGroupAccess(user, chatID, request, r)
			} else if request.Field == "t" {
				err = db.changeChatGroupName(user, chatID, request, r)
			}
		}
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
}

func (db *GoDB) changeChatGroupImage(
	rapidDB *GoDB, user *User, chatID string, request *ChatGroupModification, isBanner, isAnimated bool,
) error {
	if request.NewValue == "" {
		return nil
	}
	// Check file size
	fileSize := GetBase64BinaryLength(request.NewValue)
	if fileSize > 20*MiB {
		return nil
	}
	var filename string
	// Construct filename
	if isBanner {
		filename = "banner-chat"
	} else {
		filename = "thumbnail-chat"
	}
	// Save image
	fileRequest := &FileSubmission{
		DataBase64:    request.NewValue,
		Filename:      filename,
		ChatGroupUUID: chatID,
		IsPrivate:     false,
	}
	fileSizeMB := float64(fileSize) / float64(1*MiB)
	uUID, err := rapidDB.SaveBase64AsFile(user, fileRequest, fileSizeMB)
	if err != nil {
		return err
	}
	// Retrieve chat group
	response, txn := db.Get(GroupDB, chatID)
	if txn == nil {
		return nil
	}
	defer txn.Discard()
	chatGroup := &ChatGroup{}
	err = json.Unmarshal(response.Data, chatGroup)
	if err != nil {
		return err
	}
	// Set image url
	if isBanner {
		chatGroup.BannerURL = fmt.Sprintf("files/public/get/%s", uUID)
	} else {
		chatGroup.ThumbnailURL = fmt.Sprintf("files/public/get/%s", uUID)
	}
	jsonEntry, err := json.Marshal(chatGroup)
	if err != nil {
		return err
	}
	err = db.Update(GroupDB, txn, response.uUID, jsonEntry, map[string]string{})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) handleChatMemberModification(rapidDB *GoDB) http.HandlerFunc {
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
		// Retrieve POST payload
		request := &ChatMemberModification{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Type == "edit" {
			if request.Field == "iurl" {
				handleChatMemberImageMod(w, user, request, chatID, db, rapidDB)
			} else if request.Field == "fcm" {
				handleChatMemberFCMTokenMod(w, user, request, chatID, db)
			}
		}
	}
}

func handleChatMemberImageMod(w http.ResponseWriter, user *User,
	request *ChatMemberModification, chatID string,
	mainDB, rapidDB *GoDB,
) {
	if request.NewValue == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	// Check file size
	fileSize := GetBase64BinaryLength(request.NewValue)
	if fileSize > 20*MiB {
		http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
		return
	}
	// Are we looking at a gif file?
	_, fileExt, _, _ := GetBase64FileInformation(request.NewValue)
	uUIDStatic := ""
	var err error
	if fileExt == ".gif" {
		// gif -> save a .png version of it, too
		fileRequest := &FileSubmission{
			DataBase64:    request.NewValue,
			Filename:      fmt.Sprintf("pfp-static-%s", user.Username),
			ChatGroupUUID: chatID,
			IsPrivate:     false,
		}
		fileSizeMB := float64(fileSize) / float64(1*MiB)
		uUIDStatic, err = rapidDB.SaveBase64AsPredefinedFile(user, fileRequest, ".png", fileSizeMB)
	}
	// Save profile picture
	fileRequest := &FileSubmission{
		DataBase64:    request.NewValue,
		Filename:      fmt.Sprintf("pfp-%s", user.Username),
		ChatGroupUUID: chatID,
		IsPrivate:     false,
	}
	fileSizeMB := float64(fileSize) / float64(1*MiB)
	uUID, err := rapidDB.SaveBase64AsFile(user, fileRequest, fileSizeMB)
	// Retrieve chat member
	chatMember, txn := GetChatMember(mainDB, chatID, user.Username)
	defer txn.Discard()
	// Update Image URL
	if uUIDStatic == "" {
		chatMember.ThumbnailURL = fmt.Sprintf("files/public/get/%s", uUID)
		chatMember.ThumbnailAnimatedURL = ""
	} else {
		chatMember.ThumbnailURL = fmt.Sprintf("files/public/get/%s", uUIDStatic)
		chatMember.ThumbnailAnimatedURL = fmt.Sprintf("files/public/get/%s", uUID)
	}
	// Commit changes
	jsonEntry, err := json.Marshal(chatMember)
	err = mainDB.Update(MemberDB, txn, chatMember.UUID, jsonEntry, map[string]string{
		"chat-usr": fmt.Sprintf("%s;%s;", chatID, chatMember.Username)},
	)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func handleChatMemberFCMTokenMod(w http.ResponseWriter, user *User,
	request *ChatMemberModification, chatID string,
	mainDB *GoDB,
) {
	if request.NewValue == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	// Retrieve chat member
	chatMember, txn := GetChatMember(mainDB, chatID, user.Username)
	defer txn.Discard()
	// Does the user have this token already?
	if chatMember.FCMToken == request.NewValue {
		return
	}
	// Insert FCM Token
	chatMember.FCMToken = request.NewValue
	// Commit changes
	jsonEntry, err := json.Marshal(chatMember)
	err = mainDB.Update(MemberDB, txn, chatMember.UUID, jsonEntry, map[string]string{
		"chat-usr": fmt.Sprintf("%s;%s;", chatID, chatMember.Username)},
	)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}

func (db *GoDB) GetMainChatGroup(chatID string) (*ChatGroupEntry, bool) {
	resp, ok := db.Read(GroupDB, chatID)
	if !ok {
		return nil, false
	}
	// Retrieve chat group from database
	chatGroup := &ChatGroup{}
	err := json.Unmarshal(
		resp.Data,
		chatGroup,
	)
	if err != nil {
		return nil, false
	}
	if chatGroup.ParentUUID != "" {
		// Get parent
		resp, ok = db.Read(GroupDB, chatGroup.ParentUUID)
		if !ok {
			return nil, false
		}
		// Retrieve chat group from database
		chatGroup = &ChatGroup{}
		err = json.Unmarshal(
			resp.Data,
			chatGroup,
		)
		if err != nil {
			return nil, false
		}
	}
	return &ChatGroupEntry{
		ChatGroup: chatGroup,
		UUID:      resp.uUID,
	}, true
}

func (db *GoDB) changeChatGroupAccess(
	user *User, chatID string, request *ChatGroupModification, r *http.Request,
) error {
	// Check if user is admin
	chatGroup, chatMember, _, _ := ReadChatGroupAndMember(db, nil, nil,
		chatID, user.Username, "", r)
	if chatGroup == nil || chatMember == nil {
		return errors.New(http.StatusText(http.StatusForbidden))
	}
	userRole := chatMember.GetRoleInformation(chatGroup.ChatGroup)
	if !userRole.IsAdmin {
		return errors.New(http.StatusText(http.StatusForbidden))
	}
	// Retrieve chat group
	response, txn := db.Get(GroupDB, chatID)
	if txn == nil {
		return errors.New(http.StatusText(http.StatusNotFound))
	}
	defer txn.Discard()
	chatGroupMain := &ChatGroup{}
	err := json.Unmarshal(response.Data, chatGroupMain)
	if err != nil {
		return errors.New(http.StatusText(http.StatusInternalServerError))
	}
	// Change password (if provided) and set private flag
	if request.NewValue != "" {
		chatGroupMain.Password = request.NewValue
		chatGroupMain.IsPrivate = true
	} else {
		chatGroupMain.Password = ""
		chatGroupMain.IsPrivate = false
	}
	// Commit changes
	jsonEntry, err := json.Marshal(chatGroup)
	if err != nil {
		return errors.New(http.StatusText(http.StatusInternalServerError))
	}
	err = db.Update(GroupDB, txn, response.uUID, jsonEntry, map[string]string{})
	if err != nil {
		return errors.New(http.StatusText(http.StatusInternalServerError))
	}
	return nil
}

func (db *GoDB) changeChatGroupName(
	user *User, chatID string, request *ChatGroupModification, r *http.Request,
) error {
	// Check if user is admin
	chatGroupTmp, chatMember, _, _ := ReadChatGroupAndMember(db, nil, nil,
		chatID, user.Username, "", r)
	if chatGroupTmp == nil || chatMember == nil {
		return errors.New(http.StatusText(http.StatusForbidden))
	}
	userRole := chatMember.GetRoleInformation(chatGroupTmp.ChatGroup)
	if !userRole.IsAdmin {
		return errors.New(http.StatusText(http.StatusForbidden))
	}
	// Retrieve chat group
	response, txn := db.Get(GroupDB, chatID)
	if txn == nil {
		return nil
	}
	defer txn.Discard()
	chatGroup := &ChatGroup{}
	var err error
	err = json.Unmarshal(response.Data, chatGroup)
	if err != nil {
		return err
	}
	// Are we deleting or modifying?
	var jsonEntry []byte
	if request.NewValue == "" {
		// Delete
		txn.Discard()
		err = db.Delete(GroupDB, response.uUID, []string{})
		// We need to remove this chat group from its parent if there is one
		if chatGroup.ParentUUID != "" {
			responseMain, txnMain := db.Get(GroupDB, chatGroup.ParentUUID)
			if txnMain == nil {
				return nil
			}
			defer txnMain.Discard()
			chatGroupMain := &ChatGroup{}
			err = json.Unmarshal(responseMain.Data, chatGroupMain)
			if err != nil {
				return err
			}
			for i := 0; i < len(chatGroupMain.Subchatrooms); i++ {
				if chatGroupMain.Subchatrooms[i].UUID == response.uUID {
					chatGroupMain.Subchatrooms = append(chatGroupMain.Subchatrooms[:i], chatGroupMain.Subchatrooms[i+1:]...)
					break
				}
			}
			// Save main group
			jsonEntry, err = json.Marshal(chatGroupMain)
			if err != nil {
				return err
			}
			err = db.Update(GroupDB, txnMain, chatGroup.ParentUUID, jsonEntry, map[string]string{})
		}
	} else {
		// Modify
		chatGroup.Name = request.NewValue
		// Save
		jsonEntry, err = json.Marshal(chatGroup)
		if err != nil {
			return err
		}
		err = db.Update(GroupDB, txn, response.uUID, jsonEntry, map[string]string{})
		// We need to modify this chat group's name for its parent if there is one
		if chatGroup.ParentUUID != "" {
			responseMain, txnMain := db.Get(GroupDB, chatGroup.ParentUUID)
			if txnMain == nil {
				return nil
			}
			defer txnMain.Discard()
			chatGroupMain := &ChatGroup{}
			err = json.Unmarshal(responseMain.Data, chatGroupMain)
			if err != nil {
				return err
			}
			for i := 0; i < len(chatGroupMain.Subchatrooms); i++ {
				if chatGroupMain.Subchatrooms[i].UUID == response.uUID {
					chatGroupMain.Subchatrooms[i].Name = request.NewValue
					break
				}
			}
			// Save main group
			jsonEntry, err = json.Marshal(chatGroupMain)
			if err != nil {
				return err
			}
			err = db.Update(GroupDB, txnMain, chatGroup.ParentUUID, jsonEntry, map[string]string{})
		}
	}
	if err != nil {
		return err
	}
	return nil
}
