package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
)

const MockDB = "mxmb"

type MockingbirdConfig struct {
	Name                string `json:"t"`
	Description         string `json:"desc"`
	Username            string `json:"usr"`
	TimeCreated         string `json:"ts"`
	IsOutgoing          bool   `json:"out"`
	URL                 string `json:"url"`
	Endpoint            string `json:"endpoint"`
	AuthorizationType   string `json:"authType"`
	AuthUser            string `json:"authUser"`
	AuthPassword        string `json:"authPass"`
	PeriodicID          string `json:"periodicId"`
	ResponseType        string `json:"respType"`
	ResponseContentType string `json:"respContentType"`
	ResponseContent     string `json:"response"`
	ResponseStatusCode  int    `json:"respStatus"`
	RequestContentType  string `json:"reqContentType"`
	RequestMethod       string `json:"reqMethod"`
	RequestContent      string `json:"request"`
}

func (db *GoDB) PublicMockingbirdEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	rapidDB *GoDB, connector *Connector,
) {
	r.Route("/mockingbird/public", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		// ###########
		// ### GET ###
		// ###########
	})
}

func (db *GoDB) ProtectedMockingbirdEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth, rapidDB *GoDB, connector *Connector,
) {
	r.Route("/mockingbird/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/config", db.handleMockingbirdConfigSubmit())
		r.Post("/edit/{mockID}", db.handleMockingbirdConfigEdit())
		// ###########
		// ### GET ###
		// ###########
	})
}

func (a *MockingbirdConfig) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	if a.IsOutgoing && a.URL == "" {
		return errors.New("missing url")
	}
	return nil
}

func (db *GoDB) handleMockingbirdConfigSubmit() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &MockingbirdConfig{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Sanitize
		request.Username = user.Username
		request.TimeCreated = TimeNowIsoString()
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(MockDB, jsonEntry, map[string]string{
			"usr": FIndex(request.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleMockingbirdConfigEdit() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		mockID := chi.URLParam(r, "mockID")
		if mockID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &MockingbirdConfig{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok := db.Read(MockDB, mockID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		config := &MockingbirdConfig{}
		err := json.Unmarshal(response.Data, config)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != config.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Lock and update
		_, txn := db.Get(MockDB, mockID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		// Save
		jsonEntry, err := json.Marshal(config)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(MockDB, txn, response.uUID, jsonEntry, map[string]string{
			"usr": FIndex(config.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}
