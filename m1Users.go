package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/gofrs/uuid"
	"net/http"
)

type User struct {
	Username    string `json:"usr"`
	DisplayName string `json:"name"`
	Email       string `json:"email"`
	PassHash    string `json:"pwhash"`
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

func OpenUserDatabase() *GoDB {
	db := OpenDB("users", []string{
		"username",
	})
	return db
}

func (db *GoDB) PublicUserEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth, notificationDB *GoDB) {
	r.Route("/users/public", func(r chi.Router) {
		r.Get("/count", db.handleUserCount())
		r.Post("/signup", db.handleUserRegistration(notificationDB))
	})
}

func (db *GoDB) BasicProtectedUserEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth) {
	r.Route("/auth/private", func(r chi.Router) {
		r.Get("/signin", db.handleUserLogin())
	})
}

func (db *GoDB) ProtectedUserEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	chatGroupDB, chatMemberDB, notificationDB *GoDB, connector *Connector) {
	r.Route("/users/private", func(r chi.Router) {
		r.Post("/mod", db.handleUserModification())
		r.Post("/befriend", db.handleUserFriendRequest(chatGroupDB, chatMemberDB, notificationDB, connector))
	})
}

func (db *GoDB) handleUserCount() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, db.indices["uuid"].index.Len())
	}
}

func (db *GoDB) handleUserLogin() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		token := generateToken(user)
		_, _ = fmt.Fprintln(w, token)
	}
}

func (db *GoDB) handleUserRegistration(notificationDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Retrieve POST payload
		request := &RegisterRequest{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check Parameters
		if request.Username == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if request.Password == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Check if this user exists already
		query := fmt.Sprintf("^%s$", request.Username)
		resp, err := db.Select(map[string]string{
			"username": query,
		}, nil)
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
		}
		jsonEntry, err := json.Marshal(newUser)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(jsonEntry, map[string]string{
			"username": request.Username,
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
			_, _ = notificationDB.Insert(jsonNotification, map[string]string{
				"username": request.Username,
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
	_ = db.Lock(userUUID)
	user.DisplayName = request.NewValue
	userBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}
	err = db.Update(userUUID, userBytes, map[string]string{
		"username": user.Username,
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) changeUserPassword(user *User, userUUID string, request *UserModification) error {
	hOld := sha256.New()
	hOld.Write([]byte(request.OldValue))
	passwordHashOld := fmt.Sprintf("%x", hOld.Sum(nil))
	// Check if old and current values match
	match := subtle.ConstantTimeCompare([]byte(user.PassHash), []byte(passwordHashOld))
	if match != 1 {
		return errors.New("passwords do not match")
	}
	// Change password
	_ = db.Lock(userUUID)
	// Hash the new password
	hNew := sha256.New()
	hNew.Write([]byte(request.NewValue))
	passwordHashNew := fmt.Sprintf("%x", hNew.Sum(nil))
	user.PassHash = passwordHashNew
	userBytes, err := json.Marshal(user)
	if err != nil {
		return err
	}
	err = db.Update(userUUID, userBytes, map[string]string{
		"username": user.Username,
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) GetUserFromUsername(username string) *User {
	userQuery := fmt.Sprintf("^%s$", username)
	resp, err := db.Select(
		map[string]string{
			"username": userQuery,
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

func (db *GoDB) handleUserFriendRequest(
	chatGroupDB, chatMemberDB, notificationDB *GoDB, connector *Connector) http.HandlerFunc {
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
		chatID, err := chatMemberDB.CheckFriendGroupExist(user.Username, request.Username)
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
			RulesRead:   []string{"members"},
			RulesWrite:  []string{"members"},
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
		uUID, err := chatGroupDB.Insert(jsonEntry, map[string]string{})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Now send the friend request to the remote user by creating a notification
		notification := &Notification{
			Title:             "Friend Request",
			Description:       fmt.Sprintf("%s sent you a friend request!", user.DisplayName),
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
		notificationUUID, err := notificationDB.Insert(jsonNotification, map[string]string{
			"username": request.Username,
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
			Message:       fmt.Sprintf("%s sent you a friend request!", user.DisplayName),
		}
		_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	}
}
