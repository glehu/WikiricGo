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
}

type FriendList struct {
	Friends []*FriendGroup `json:"friends"`
}

type FriendGroup struct {
	*ChatMemberEntry `json:"friend"`
	ChatGroupUUID    string `json:"pid"`
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
			r.Get("/friends", db.handleGetFriends(chatMemberDB))
		})
	})
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
			http.Error(w, err.Error(), http.StatusBadRequest)
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
				"chat-usr": fmt.Sprintf("%s\\|%s", uUID, user.Username),
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
		response, ok := db.Read(chatID)
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

func ReadChatGroupAndMember(
	chatGroupDB, chatMemberDB, notificationDB *GoDB,
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
	dataOriginal, ok := chatGroupDB.Read(chatID)
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
		chatID = chatGroupOriginal.ParentUUID
		dataMain, ok = chatGroupDB.Read(chatID)
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
		"%s\\|%s",
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
			"chat-usr": query,
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
					"chat-usr":    fmt.Sprintf("%s\\|%s", chatID, username),
					"user-friend": fmt.Sprintf("%s\\|%s", username, refUsername),
				}
				go func() {
					err = notifyFriendRequestAccept(refUsername, user.DisplayName, notificationDB, connector, chatID, password)
					if err != nil {
						fmt.Println(err)
						return
					}
				}()
			}
		} else {
			// No DM group
			roles = []string{"member"}
			indices = map[string]string{
				"chat-usr": fmt.Sprintf("%s\\|%s", chatID, username),
			}
			go func() {
				container := &ChatGroupEntry{
					ChatGroup: &chatGroup,
					UUID:      dataOriginal.uUID,
				}
				err = notifyJoin(user.DisplayName, chatMemberDB, notificationDB, connector, container)
				if err != nil {
					fmt.Println(err)
					return
				}
			}()
		}
		chatMember = &ChatMember{
			Username:             username,
			ChatGroupUUID:        chatID,
			DisplayName:          username,
			Roles:                roles,
			PublicKey:            "", // Public Key will be submitted by the client
			ThumbnailURL:         "",
			ThumbnailAnimatedURL: "",
			BannerURL:            "",
			BannerAnimatedURL:    "",
		}
		newMember, err := json.Marshal(chatMember)
		_, err = chatMemberDB.Insert(newMember, indices)
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
		response, txn := db.Get(chatID)
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
		err = db.Update(txn, response.uUID, jsonEntry, map[string]string{})
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
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve chat group etc.
		_, chatMember, _, err := ReadChatGroupAndMember(
			db, chatMemberDB, nil, nil, chatID, request.Username, "", r)
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
		_, txn := chatMemberDB.Get(chatMember.UUID)
		defer txn.Discard()
		jsonEntry, err := json.Marshal(chatMember)
		err = chatMemberDB.Update(txn, chatMember.UUID, jsonEntry, map[string]string{
			"chat-usr": fmt.Sprintf("%s\\|%s", chatID, chatMember.Username)},
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
		query := fmt.Sprintf("%s\\|", chatID)
		resp, err := chatMemberDB.Select(
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

func notifyFriendRequestAccept(refUsername, selfName string,
	notificationDB *GoDB, connector *Connector, chatID, password string,
) error {
	notification := &Notification{
		Title:             "Friend Request Accepted",
		Description:       fmt.Sprintf("%s accepted your friend request!", selfName),
		Type:              "frequest",
		TimeCreated:       TimeNowIsoString(),
		RecipientUsername: refUsername,
		ClickAction:       "join",
		ClickModule:       "chat",
		ClickUUID:         fmt.Sprintf("%s?pw=%s", chatID, password),
	}
	jsonNotification, err := json.Marshal(notification)
	if err != nil {
		return err
	}
	notificationUUID, err := notificationDB.Insert(jsonNotification, map[string]string{
		"usr": refUsername,
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
		Username:      selfName,
		Message:       fmt.Sprintf("%s accepted your friend request!", selfName),
	}
	_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	return nil
}

func notifyJoin(selfName string, chatMemberDB, notificationDB *GoDB, connector *Connector, chatGroup *ChatGroupEntry,
) error {
	// Retrieve all members of this chat group
	query := fmt.Sprintf("%s\\|", chatGroup.UUID)
	resp, err := chatMemberDB.Select(map[string]string{"chat-usr": query}, nil)
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
		notificationUUID, err := notificationDB.Insert(jsonNotification, map[string]string{
			"usr": chatMember.Username,
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

func (db *GoDB) handleGetFriends(chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve friends
		query := fmt.Sprintf("((%s\\|.+)|(.+\\|%s))\\|", user.Username, user.Username)
		resp, err := chatMemberDB.Select(map[string]string{"user-friend": query}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		responseMember := <-resp
		if len(responseMember) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		members := FriendList{
			Friends: make([]*FriendGroup, len(responseMember)),
		}
		for i, entry := range responseMember {
			chatMember := &ChatMember{}
			err = json.Unmarshal(entry.Data, chatMember)
			if err == nil {
				members.Friends[i] = &FriendGroup{
					ChatMemberEntry: &ChatMemberEntry{
						ChatMember: chatMember,
						UUID:       entry.uUID,
					},
					ChatGroupUUID: chatMember.ChatGroupUUID,
				}
			}
		}
		if len(members.Friends) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		render.JSON(w, r, members)
	}
}
