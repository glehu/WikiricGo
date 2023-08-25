package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
)

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
	UUID string
}

type NotificationsResponse struct {
	Notifications []*NotificationContainer
}

func OpenNotificationDatabase() *GoDB {
	db := OpenDB(
		"notifications", []string{
			"username",
		},
	)
	return db
}

func (db *GoDB) ProtectedNotificationEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
) {
	r.Route(
		"/notification/private", func(r chi.Router) {
			r.Get("/read", db.handleNotificationRead())
			r.Get("/get/{notificationID}", db.handleNotificationGet())
			r.Get("/delete/{notificationID}", db.handleNotificationDelete())
		},
	)
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
		resp, lid := db.Get(notificationID)
		if lid == "" {
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
		resp, lid := db.Get(notificationID)
		if lid == "" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
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
		db.Unlock(notificationID, lid)
		err = db.Delete(notificationID)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Do we need to delete other notifications as well?
		tidyQuery := r.URL.Query().Get("tidy")
		if tidyQuery != "" {
			query := fmt.Sprintf("^%s$", user.Username)
			resp, err := db.Select(map[string]string{
				"username": query,
			}, nil)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			response := <-resp
			if len(response) > 0 {
				// Delete unimportant notifications
				for _, notifEntry := range response {
					notification = &Notification{}
					err = json.Unmarshal(notifEntry.Data, notification)
					if err == nil {
						if notification.Type != "frequest" {
							_ = db.Delete(notifEntry.uUID)
						}
					}
				}
			}
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
		query := fmt.Sprintf("^%s$", user.Username)
		resp, err := db.Select(map[string]string{
			"username": query,
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
