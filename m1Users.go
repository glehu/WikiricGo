package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid"
	"net/http"
	"strings"
)

const UserDB = "m1"

type User struct {
	Username    string       `json:"usr"`
	DisplayName string       `json:"name"`
	Email       string       `json:"email"`
	PassHash    string       `json:"pwhash"`
	Badges      []*UserBadge `json:"badges"`
	DateCreated string       `json:"ts"`
}

type UserBadge struct {
	Name        string `json:"t"`
	Description string `json:"desc"`
	Experience  int64  `json:"xp"`
	Date        string `json:"ts"`
	BadgeID     string `json:"id"`
}

type RegisterRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

type UserModification struct {
	Type     string `json:"type"`
	Field    string `json:"field"`
	OldValue string `json:"old"`
	NewValue string `json:"new"`
}

type FriendRequest struct {
	Username string `json:"usr"`
	Message  string `json:"msg"`
}

type LoginResponse struct {
	HttpCode    int16  `json:"httpCode"`
	Token       string `json:"token"`
	ExpiresInMs int64  `json:"expiresInMs"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

type UserStatusRequest struct {
	Usernames []string `json:"usernames"`
}

type UserStatusResponse struct {
	Users []*UserStatus `json:"users"`
}

type UserStatus struct {
	Username string `json:"usr"`
	Status   string `json:"status"`
}

func (db *GoDB) PublicUserEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth, rapidDB *GoDB) {
	r.Route("/users/public", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/signup", db.handleUserRegistration(rapidDB))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/count", db.handleUserCount())
	})
}

func (db *GoDB) BasicProtectedUserEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth) {
	r.Route("/auth/private", func(r chi.Router) {
		// ###########
		// ### GET ###
		// ###########
		r.Get("/signin", db.handleUserLogin())
	})
}

func (db *GoDB) ProtectedUserEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth, rapidDB *GoDB, connector *Connector,
) {
	r.Route("/users/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/mod", db.handleUserModification())
		r.Post("/befriend", db.handleUserFriendRequest(rapidDB, connector))
		r.Post("/status", db.handleUserGetStatus(connector))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/state", handleUserSetState(connector))
	})
}

func (db *GoDB) handleUserCount() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users := db.getUserCount()
		if users == -1 {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, users)
	}
}

func (db *GoDB) getUserCount() int64 {
	count := 0
	err := db.db.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()
		for it.Rewind(); it.Valid(); it.Next() {
			count += 1
		}
		return nil
	})
	if err != nil {
		return -1
	}
	countHalved := float64(count) / 2.0
	return int64(countHalved)
}

func (db *GoDB) handleUserLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		token, expiresInMs := generateToken(user)
		response := &LoginResponse{
			HttpCode:    200,
			Token:       token,
			ExpiresInMs: expiresInMs,
			Username:    user.Username,
			DisplayName: user.DisplayName,
		}
		render.JSON(w, r, response)
	}
}

func (db *GoDB) handleUserRegistration(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Retrieve POST payload
		request := &RegisterRequest{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check Parameters
		if request.Username == "" {
			http.Error(w, "missing username", http.StatusBadRequest)
			return
		}
		if request.Password == "" {
			http.Error(w, "missing password", http.StatusBadRequest)
			return
		}
		if strings.Contains(request.Username, ";") {
			http.Error(w, "illegal character in username", http.StatusBadRequest)
			return
		}
		// Check if this user exists already
		query := FIndex(request.Username)
		resp, err := db.Select(UserDB, map[string]string{
			"usr": query,
		}, &SelectOptions{
			MaxResults: 1,
			Page:       0,
			Skip:       0,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		if len(response) > 0 {
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
		// Sanitize
		if request.DisplayName == "" {
			request.DisplayName = request.Username
		}
		// Hash the password
		h := sha256.New()
		h.Write([]byte(request.Password))
		passwordHash := fmt.Sprintf("%x", h.Sum(nil))
		// Create new user
		newUser := &User{
			Username:    request.Username,
			DisplayName: request.DisplayName,
			Email:       request.Email,
			PassHash:    passwordHash,
			DateCreated: TimeNowIsoString(),
		}
		jsonEntry, err := json.Marshal(newUser)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(UserDB, jsonEntry, map[string]string{
			"usr": FIndex(request.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
		// Add welcome notification for the new user! Yay!
		notification := &Notification{
			Title:             fmt.Sprintf("Hey, %s!", request.DisplayName),
			Description:       "Welcome to wikiric! Enjoy your stay :)",
			Type:              "info",
			TimeCreated:       TimeNowIsoString(),
			RecipientUsername: request.Username,
			ClickAction:       "",
			ClickModule:       "",
			ClickUUID:         "",
		}
		jsonNotification, err := json.Marshal(notification)
		if err == nil {
			_, _ = rapidDB.Insert(NotifyDB, jsonNotification, map[string]string{
				"usr": FIndex(request.Username),
			})
		}
	}
}

func (a *RegisterRequest) Bind(_ *http.Request) error {
	if a.Username == "" {
		return errors.New("missing username")
	}
	return nil
}

func (a *UserModification) Bind(_ *http.Request) error {
	if a.Type == "" {
		return errors.New("missing type")
	}
	return nil
}

func (a *FriendRequest) Bind(_ *http.Request) error {
	if a.Username == "" {
		return errors.New("missing username")
	}
	return nil
}

func (a *UserStatusRequest) Bind(_ *http.Request) error {
	if a.Usernames == nil {
		return errors.New("missing usernames")
	}
	return nil
}

func (db *GoDB) handleUserModification() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		userUUID := r.Context().Value("userID").(string)
		if userUUID == "" {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &UserModification{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check what action is required
		var err error
		if request.Type == "edit" {
			if request.Field == "name" {
				err = db.changeUserDisplayName(user, userUUID, request)
			} else if request.Field == "pw" {
				err = db.changeUserPassword(user, userUUID, request)
			}
		}
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
}

func (db *GoDB) changeUserDisplayName(user *User, userUUID string, request *UserModification) error {
	_, txn := db.Get(UserDB, userUUID)
	defer txn.Discard()
	user.DisplayName = request.NewValue
	userBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}
	err = db.Update(UserDB, txn, userUUID, userBytes, map[string]string{
		"usr": FIndex(user.Username),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) changeUserPassword(user *User, userUUID string, request *UserModification) error {
	_, txn := db.Get(UserDB, userUUID)
	defer txn.Discard()
	hOld := sha256.New()
	hOld.Write([]byte(request.OldValue))
	passwordHashOld := fmt.Sprintf("%x", hOld.Sum(nil))
	// Check if old and current values match
	match := subtle.ConstantTimeCompare([]byte(user.PassHash), []byte(passwordHashOld))
	if match != 1 {
		return errors.New("passwords do not match")
	}
	// Hash the new password
	hNew := sha256.New()
	hNew.Write([]byte(request.NewValue))
	passwordHashNew := fmt.Sprintf("%x", hNew.Sum(nil))
	user.PassHash = passwordHashNew
	userBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}
	err = db.Update(UserDB, txn, userUUID, userBytes, map[string]string{
		"usr": FIndex(user.Username),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) GetUserFromUsername(username string) *User {
	resp, err := db.Select(UserDB,
		map[string]string{
			"usr": FIndex(username),
		}, nil,
	)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	response := <-resp
	if len(response) < 1 {
		return nil
	}
	userFromDB := &User{}
	err = json.Unmarshal(response[0].Data, userFromDB)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return userFromDB
}

func (db *GoDB) handleUserFriendRequest(rapidDB *GoDB, connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &FriendRequest{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check if there's already a friend group
		chatID, err := db.CheckFriendGroupExist(user.Username, request.Username)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if chatID != "" {
			http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
			return
		}
		// There is no DM group -> Create one
		// Create a special password needed to join the private DMs
		passwordUUID, err := uuid.NewV4()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		password := passwordUUID.String()
		chatGroup := &ChatGroup{
			Name:        fmt.Sprintf("|%s||%s|", user.Username, request.Username),
			Type:        "dm",
			Description: "",
			TimeCreated: TimeNowIsoString(),
			RulesRead:   []string{"member"},
			RulesWrite:  []string{"member"},
			Roles: []ChatRole{
				{
					Name:     "owner",
					Index:    20_000,
					ColorHex: "",
					IsAdmin:  true,
				},
				{
					Name:     "member",
					Index:    40_000,
					ColorHex: "",
					IsAdmin:  false,
				},
			},
			IsPrivate:            true,
			Password:             password,
			Subchatrooms:         nil,
			ParentUUID:           "",
			ThumbnailURL:         "",
			ThumbnailAnimatedURL: "",
			BannerURL:            "",
			BannerAnimatedURL:    "",
		}
		jsonEntry, err := json.Marshal(chatGroup)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(GroupDB, jsonEntry, map[string]string{})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		var friendRequestMsg string
		if request.Message == "" {
			friendRequestMsg = fmt.Sprintf("%s sent you a friend request!", user.DisplayName)
		} else {
			friendRequestMsg = fmt.Sprintf(
				"%s sent you a friend request with a message:\n\n%s", user.DisplayName, request.Message)
		}
		// Now send the friend request to the remote user by creating a notification
		notification := &Notification{
			Title:             "Friend Request",
			Description:       friendRequestMsg,
			Type:              "frequest",
			TimeCreated:       TimeNowIsoString(),
			RecipientUsername: request.Username,
			ClickAction:       "join",
			ClickModule:       "chat",
			ClickUUID:         fmt.Sprintf("%s?pw=%s&ref=%s", uUID, password, user.Username),
		}
		jsonNotification, err := json.Marshal(notification)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		notificationUUID, err := rapidDB.Insert(NotifyDB, jsonNotification, map[string]string{
			"usr": FIndex(request.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Now send a message via the connector
		connector.SessionsMu.RLock()
		defer connector.SessionsMu.RUnlock()
		session, ok := connector.Sessions.Get(request.Username)
		if !ok {
			return
		}
		cMSG := &ConnectorMsg{
			Type:          "[s:NOTIFICATION]",
			Action:        "frequest",
			ReferenceUUID: notificationUUID,
			Username:      user.DisplayName,
			Message:       friendRequestMsg,
		}
		_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	}
}

func (db *GoDB) handleUserGetStatus(connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &UserStatusRequest{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		activeUsers := &UserStatusResponse{Users: make([]*UserStatus, 0)}
		connector.SessionsMu.RLock()
		defer connector.SessionsMu.RUnlock()
		for _, username := range request.Usernames {
			usr, ok := connector.Sessions.Get(username)
			if ok {
				activeUsers.Users = append(activeUsers.Users, &UserStatus{
					Username: username,
					Status:   usr.Status,
				})
			} else {
				activeUsers.Users = append(activeUsers.Users, &UserStatus{
					Username: username,
					Status:   "offline",
				})
			}
		}
		render.JSON(w, r, activeUsers)
	}
}

func handleUserSetState(connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		status := r.URL.Query().Get("status")
		if status == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		connector.SessionsMu.RLock()
		usr, ok := connector.Sessions.Get(user.Username)
		if !ok {
			connector.SessionsMu.RUnlock()
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		usr.Status = status
		connector.SessionsMu.RUnlock()
		connector.SessionsMu.Lock()
		connector.Sessions.Set(user.Username, usr)
		connector.SessionsMu.Unlock()
	}
}
