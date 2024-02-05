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

const SandboxDB = "m14"

type Sandbox struct {
	Name          string `json:"t"`
	Username      string `json:"usr"`
	Description   string `json:"desc"`
	TimeCreated   string `json:"ts"`
	AnalyticsUUID string `json:"ana"` // Views, likes etc. will be stored in a separate database
}

type SandboxElement struct {
	UUID          string  `json:"uuid"`
	Name          string  `json:"t"`
	Type          string  `json:"type"`
	Username      string  `json:"usr"`
	Description   string  `json:"desc"`
	TimeCreated   string  `json:"ts"`
	ReferenceUUID string  `json:"ref"`
	ParentUUID    string  `json:"pid"`
	AnalyticsUUID string  `json:"ana"` // Views, likes etc. will be stored in a separate database
	PosX          float64 `json:"x"`
	PosY          float64 `json:"y"`
	Width         float64 `json:"w"`
	Height        float64 `json:"h"`
	Hide          bool    `json:"hide"`
}

type SandboxEntry struct {
	UUID string `json:"uid"`
	*Sandbox
	*Analytics
}

type SandboxElementEntry struct {
	UUID string `json:"uid"`
	*SandboxElement
	*Analytics
}

type SandboxContainer struct {
	Sandboxes []SandboxEntry `json:"sandboxes"`
}

type SandboxElementsContainer struct {
	Elements []SandboxElementEntry `json:"elements"`
}

func (db *GoDB) ProtectedSandboxEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	connector *Connector,
) {
	r.Route("/sandbox/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/create", db.handleSandboxCreate(connector))
		r.Post("/mod/{sandboxID}", db.handleSandboxModification())
		r.Post("/add/{sandboxID}", db.handleSandboxElementCreate())
		r.Post("/edit/{elementID}", db.handleSandboxElementEdit())
		// ###########
		// ### GET ###
		// ###########
		r.Get("/get", db.handleSandboxGet())
		r.Get("/view/{sandboxID}", db.handleSandboxView())
		r.Get("/delete/{sandboxID}", db.handleSandboxDelete())
		r.Get("/remove/{elementID}", db.handleSandboxElementDelete())
	})
}

func (a *Sandbox) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	return nil
}

func (a *SandboxElement) Bind(_ *http.Request) error {
	if a.Type == "" {
		return errors.New("missing type")
	}
	if a.ParentUUID == "" {
		return errors.New("missing parent id")
	}

	return nil
}

func (db *GoDB) handleSandboxCreate(connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &Sandbox{}
		if err := render.Bind(r, request); err != nil {
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
		uUID, err := db.Insert(SandboxDB, jsonEntry, map[string]string{
			"usr": FIndex(request.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleSandboxGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve user's sandboxes
		resp, err := db.Select(SandboxDB, map[string]string{
			"usr": FIndex(user.Username),
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		if len(response) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		responseContainer := SandboxContainer{Sandboxes: make([]SandboxEntry, len(response))}
		for _, sandboxResponse := range response {
			sandbox := &Sandbox{}
			err = json.Unmarshal(sandboxResponse.Data, sandbox)
			if err != nil {
				fmt.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Is there an analytics entry?
			analytics := &Analytics{}
			if sandbox.AnalyticsUUID != "" {
				anaBytes, txn := db.Get(AnaDB, sandbox.AnalyticsUUID)
				if txn != nil {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						txn.Discard()
						analytics = &Analytics{}
					}
				}
			}
			responseContainer.Sandboxes = append(responseContainer.Sandboxes, SandboxEntry{
				UUID:      sandboxResponse.uUID,
				Sandbox:   sandbox,
				Analytics: analytics,
			})
		}
		render.JSON(w, r, responseContainer)
	}
}

func (db *GoDB) handleSandboxModification() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		sandboxID := chi.URLParam(r, "sandboxID")
		if sandboxID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &SandboxEntry{}
		var err error
		if err = render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok := db.Read(SandboxDB, sandboxID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		sandbox := &Sandbox{}
		err = json.Unmarshal(response.Data, sandbox)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != sandbox.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve sandbox transaction
		_, txn := db.Get(SandboxDB, sandboxID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer txn.Discard()
		// Save by overriding
		jsonEntry, err := json.Marshal(request.Sandbox)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(SandboxDB, txn, response.uUID, jsonEntry, map[string]string{
			"usr": FIndex(sandbox.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleSandboxView() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		sandboxID := chi.URLParam(r, "sandboxID")
		if sandboxID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok := db.Read(SandboxDB, sandboxID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		sandbox := &Sandbox{}
		err := json.Unmarshal(response.Data, sandbox)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != sandbox.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve all elements of this sandbox
		resp, err := db.Select(SandboxDB, map[string]string{
			"usr-pid": fmt.Sprintf("%s-%s", FIndex(user.Username), sandboxID),
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		responseElements := <-resp
		if len(responseElements) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		responseContainer := SandboxElementsContainer{Elements: make([]SandboxElementEntry, len(responseElements))}
		for _, sandboxResponse := range responseElements {
			element := &SandboxElement{}
			err = json.Unmarshal(sandboxResponse.Data, element)
			if err != nil {
				fmt.Println(err)
				continue
			}
			// Is there an analytics entry?
			analytics := &Analytics{}
			if element.AnalyticsUUID != "" {
				anaBytes, txn := db.Get(AnaDB, element.AnalyticsUUID)
				if txn != nil {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						txn.Discard()
						analytics = &Analytics{}
					}
				}
			}
			responseContainer.Elements = append(responseContainer.Elements, SandboxElementEntry{
				UUID:           sandboxResponse.uUID,
				SandboxElement: element,
				Analytics:      analytics,
			})
		}
		render.JSON(w, r, responseContainer)
	}
}

func (db *GoDB) handleSandboxElementCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		sandboxID := chi.URLParam(r, "sandboxID")
		if sandboxID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok := db.Read(SandboxDB, sandboxID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		sandbox := &Sandbox{}
		err := json.Unmarshal(response.Data, sandbox)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != sandbox.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &SandboxElement{}
		if err := render.Bind(r, request); err != nil {
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
		uUID, err := db.Insert(SandboxDB, jsonEntry, map[string]string{
			"usr-pid": fmt.Sprintf("%s-%s", FIndex(user.Username), sandboxID),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleSandboxElementEdit() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		elementID := chi.URLParam(r, "elementID")
		if elementID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &SandboxElementEntry{}
		var err error
		if err = render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok := db.Read(SandboxDB, elementID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		sandboxElement := &SandboxElement{}
		err = json.Unmarshal(response.Data, sandboxElement)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != sandboxElement.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve sandbox element transaction
		_, txn := db.Get(SandboxDB, elementID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer txn.Discard()
		// Save by overriding
		jsonEntry, err := json.Marshal(request.SandboxElement)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(SandboxDB, txn, response.uUID, jsonEntry, map[string]string{})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleSandboxDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		sandboxID := chi.URLParam(r, "sandboxID")
		if sandboxID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok := db.Read(SandboxDB, sandboxID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		sandbox := &Sandbox{}
		err := json.Unmarshal(response.Data, sandbox)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != sandbox.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Is there an analytics entry?
		if sandbox.AnalyticsUUID != "" {
			_ = db.Delete(AnaDB, sandbox.AnalyticsUUID, []string{})
		}
		// Delete item
		_ = db.Delete(SandboxDB, sandboxID, []string{"usr"})
	}
}

func (db *GoDB) handleSandboxElementDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		elementID := chi.URLParam(r, "elementID")
		if elementID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok := db.Read(SandboxDB, elementID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		element := &SandboxElement{}
		err := json.Unmarshal(response.Data, element)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != element.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Is there an analytics entry?
		if element.AnalyticsUUID != "" {
			_ = db.Delete(AnaDB, element.AnalyticsUUID, []string{})
		}
		// Delete item
		_ = db.Delete(SandboxDB, elementID, []string{"usr-pid"})
	}
}
