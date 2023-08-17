package main

import (
	"crypto/sha256"
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
	UUID     uuid.UUID `json:"uuid"`
	Username string    `json:"usr"`
	Email    string    `json:"email"`
	PassHash string    `json:"pwhash"`
}

type registerRequest struct {
	Username string `json:"username"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func OpenUserDatabase() *GoDB {
	db := OpenDB("users", []string{
		"uuid",
		"username",
	})
	return db
}

func (db *GoDB) UserEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth) {
	r.Route("/users", func(r chi.Router) {
		r.Post("/signup", db.handleRegisterUser())
	})
}

func (db *GoDB) handleRegisterUser() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		request := &registerRequest{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
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
		// Hash the password
		h := sha256.New()
		h.Write([]byte(request.Password))
		passwordHash := fmt.Sprintf("%x", h.Sum(nil))
		// Create new user
		uUID, err := uuid.NewV7()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		newUser := &User{
			UUID:     uUID,
			Username: request.Username,
			Email:    request.Email,
			PassHash: passwordHash,
		}
		jsonEntry, err := json.Marshal(newUser)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Insert(jsonEntry, map[string]string{
			"uuid":     uUID.String(),
			"username": request.Username,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, err = fmt.Fprintln(w, newUser.UUID.String())
		if err != nil {
			return
		}
	}
}

func (a *registerRequest) Bind(r *http.Request) error {
	// a.Article is nil if no Article fields are sent in the request. Return an
	// error to avoid a nil pointer dereference.
	if a.Username == "" {
		return errors.New("missing username")
	}
	return nil
}
