package main

import (
	"encoding/json"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
)

const NotifyDB = "m9"

type Notification struct {
	Title             string `json:"t"`
	Description       string `json:"desc"`
	Type              string `json:"type"`
	TimeCreated       string `json:"ts"`
	RecipientUsername string `json:"usr"`
	ClickAction       string `json:"act"`
	ClickModule       string `json:"mod"`
	ClickUUID         string `json:"id"`
}

type NotificationContainer struct {
	*Notification
	UUID string `json:"uid"`
}

type NotificationsResponse struct {
	Notifications []*NotificationContainer
}

func (db *GoDB) ProtectedNotificationEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
) {
	r.Route("/notification/private", func(r chi.Router) {
		// ###########
		// ### GET ###
		// ###########
		r.Get("/read", db.handleNotificationRead())
		r.Get("/get/{notificationID}", db.handleNotificationGet())
		r.Get("/delete/{notificationID}", db.handleNotificationDelete())
		r.Get("/tidy", db.handleNotificationTidy())
	})
}

func (db *GoDB) handleNotificationGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		notificationID := chi.URLParam(r, "notificationID")
		if notificationID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get notification
		resp, ok := db.Read(NotifyDB, notificationID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		notification := &Notification{}
		err := json.Unmarshal(resp.Data, notification)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user is retrieving a notification of his own
		if notification.RecipientUsername != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		render.JSON(w, r, notification)
	}
}

func (db *GoDB) handleNotificationDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		notificationID := chi.URLParam(r, "notificationID")
		if notificationID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get notification
		resp, txn := db.Get(NotifyDB, notificationID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		notification := &Notification{}
		err := json.Unmarshal(resp.Data, notification)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user is deleting a notification of his own
		if notification.RecipientUsername != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		err = db.Delete(NotifyDB, notificationID, []string{"usr"})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleNotificationRead() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		query := FIndex(user.Username)
		resp, err := db.Select(NotifyDB, map[string]string{
			"usr": query,
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		notifications := &NotificationsResponse{Notifications: make([]*NotificationContainer, 0)}
		if len(response) < 1 {
			render.JSON(w, r, notifications)
			return
		}
		// Retrieve notifications
		for _, notifEntry := range response {
			notification := &Notification{}
			err = json.Unmarshal(notifEntry.Data, notification)
			if err == nil {
				notifications.Notifications = append(notifications.Notifications, &NotificationContainer{
					Notification: notification,
					UUID:         notifEntry.uUID,
				})
			}
		}
		render.JSON(w, r, notifications)
	}
}

func (db *GoDB) handleNotificationTidy() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		query := FIndex(user.Username)
		resp, err := db.Select(NotifyDB, map[string]string{
			"usr": query,
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		if len(response) > 0 {
			// Delete unimportant notifications
			for _, notifEntry := range response {
				notification := &Notification{}
				err = json.Unmarshal(notifEntry.Data, notification)
				if err == nil {
					if notification.Type != "frequest" {
						_ = db.Delete(NotifyDB, notifEntry.uUID, []string{"usr"})
					}
				}
			}
		}
	}
}
