package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
)

type User struct {
	Username    string `json:"usr"`
	DisplayName string `json:"name"`
	Email       string `json:"email"`
	PassHash    string `json:"pwhash"`
}

type registerRequest struct {
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
	Email       string `json:"email"`
	Password    string `json:"password"`
}

func OpenUserDatabase() *GoDB {
	db := OpenDB("users", []string{
		"username",
	})
	return db
}

func (db *GoDB) PublicUserEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth) {
	r.Route("/users/public", func(r chi.Router) {
		r.Get("/count", db.handleUserCount())
		r.Post("/signup", db.handleUserRegistration())
	})
}

func (db *GoDB) ProtectedUserEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth) {
	r.Route("/users/private", func(r chi.Router) {
		r.Get("/signin", db.handleUserLogin())
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

func (db *GoDB) handleUserRegistration() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Retrieve POST payload
		request := &registerRequest{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
	}
}

func (a *registerRequest) Bind(_ *http.Request) error {
	if a.Username == "" {
		return errors.New("missing username")
	}
	return nil
}
