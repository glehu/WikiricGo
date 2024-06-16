package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/segmentio/asm/ascii"
	"io"
	"net/http"
	"regexp"
	"strings"
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
	Group               string `json:"group"`
}

type MockingBirdConfigEntry struct {
	UUID string `json:"uid"`
	MockingbirdConfig
}

type MockingBirdConfigContainer struct {
	Configs []MockingBirdConfigEntry `json:"configs"`
}

type MockingBirdAnalytics struct {
	Endpoint            string          `json:"endpoint"`
	IsOutgoing          bool            `json:"out"`
	TimeCreated         string          `json:"ts"`
	RequestContentType  string          `json:"reqContentType"`
	RequestMethod       string          `json:"reqMethod"`
	RequestContent      string          `json:"request"`
	RequestHeaders      []RequestHeader `json:"reqHeaders"`
	AuthorizationType   string          `json:"authType"`
	AuthUser            string          `json:"authUser"`
	AuthPassword        string          `json:"authPass"`
	ResponseType        string          `json:"respType"`
	ResponseContentType string          `json:"respContentType"`
	ResponseContent     string          `json:"response"`
	ResponseStatusCode  int             `json:"respStatus"`
}

type RequestHeader struct {
	Name  string `json:"t"`
	Value string `json:"val"`
}

// https://wikiric.xyz/mock/u/randomuser-createItem
// https://wikiric.xyz/mock/u/randomuser-deleteItem
// https://wikiric.xyz/mock/u/randomuser-viewItem

func (db *GoDB) PublicMockingbirdEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	rapidDB *GoDB, connector *Connector,
) {
	r.Route("/mock/u", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/{usr}-{endpoint}", db.handleMockingbirdPost(connector, "post"))
		r.Put("/{usr}-{endpoint}", db.handleMockingbirdPost(connector, "put"))
		r.Patch("/{usr}-{endpoint}", db.handleMockingbirdPost(connector, "patch"))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/{usr}-{endpoint}", db.handleMockingbirdGet(connector, "get"))
		r.Delete("/{usr}-{endpoint}", db.handleMockingbirdGet(connector, "delete"))
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
		r.Get("/configs", db.handleMockingbirdGetConfigs())
		r.Get("/delete/{mockID}", db.handleMockingbirdConfigDelete())
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
		// Only letters and numbers allowed
		match, _ := regexp.MatchString("^\\w+$", request.Endpoint)
		if !match {
			http.Error(w, "illegal character(s) in endpoint for pattern ^\\w+$", http.StatusBadRequest)
			return
		}
		// Sanitize
		request.Username = user.Username
		request.TimeCreated = TimeNowIsoString()
		if request.ResponseContentType == "" {
			request.ResponseContentType = "text/plain"
		}
		if request.RequestContentType == "" {
			request.RequestContentType = "text/plain"
		}
		if request.ResponseStatusCode == 0 {
			request.ResponseStatusCode = 200
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(MockDB, jsonEntry, map[string]string{
			"usr-endpoint": fmt.Sprintf(
				"%s%s%s",
				FIndex(request.Username),
				FIndex(request.Endpoint),
				FIndex(strings.ToLower(request.RequestMethod))),
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
		requestConfig := &MockingbirdConfig{}
		if err := render.Bind(r, requestConfig); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Only letters and numbers allowed
		match, _ := regexp.MatchString("^\\w+$", requestConfig.Endpoint)
		if !match {
			http.Error(w, "illegal character(s) in endpoint for pattern ^\\w+$", http.StatusBadRequest)
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
		// Sanitize
		if requestConfig.ResponseContentType == "" {
			requestConfig.ResponseContentType = "text/plain"
		}
		if requestConfig.RequestContentType == "" {
			requestConfig.RequestContentType = "text/plain"
		}
		if requestConfig.ResponseStatusCode == 0 {
			requestConfig.ResponseStatusCode = 200
		}
		// Lock and update
		_, txn := db.Get(MockDB, mockID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		// Save
		jsonEntry, err := json.Marshal(requestConfig)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(MockDB, txn, response.uUID, jsonEntry, map[string]string{
			"usr-endpoint": fmt.Sprintf(
				"%s%s%s",
				FIndex(requestConfig.Username),
				FIndex(requestConfig.Endpoint),
				FIndex(strings.ToLower(requestConfig.RequestMethod))),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleMockingbirdGetConfigs() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		resp, err := db.Select(MockDB, map[string]string{
			"usr-endpoint": FIndex(user.Username),
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		container := &MockingBirdConfigContainer{make([]MockingBirdConfigEntry, 0)}
		responseRef := <-resp
		if len(responseRef) < 1 {
			render.JSON(w, r, container)
			return
		}
		var config *MockingbirdConfig
		for _, entry := range responseRef {
			config = &MockingbirdConfig{}
			err = json.Unmarshal(entry.Data, config)
			if err != nil {
				continue
			}
			container.Configs = append(container.Configs, MockingBirdConfigEntry{
				UUID:              entry.uUID,
				MockingbirdConfig: *config,
			})
		}
		// Respond to client
		render.JSON(w, r, container)
	}
}

func (db *GoDB) GetMockingbirdConfigFromUserEndpoint(user, endpoint, method string) *MockingBirdConfigEntry {
	if user == "" || endpoint == "" {
		return nil
	}
	resp, err := db.Select(MockDB, map[string]string{
		"usr-endpoint": fmt.Sprintf(
			"%s%s%s",
			FIndex(user),
			FIndex(endpoint),
			FIndex(strings.ToLower(method))),
	}, &SelectOptions{
		MaxResults: 1,
		Page:       0,
		Skip:       0,
	})
	if err != nil {
		return nil
	}
	responseRef := <-resp
	if len(responseRef) < 1 {
		return nil
	}
	config := &MockingbirdConfig{}
	err = json.Unmarshal(responseRef[0].Data, config)
	if err != nil {
		return nil
	}
	return &MockingBirdConfigEntry{
		UUID:              responseRef[0].uUID,
		MockingbirdConfig: *config,
	}
}

func (db *GoDB) handleMockingbirdPost(connector *Connector, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// timeStart := time.Now()
		usrParam := chi.URLParam(r, "usr")
		if usrParam == "" {
			http.Error(w, "wikiric mockingbird: missing user", http.StatusBadRequest)
			return
		}
		endpointParam := chi.URLParam(r, "endpoint")
		if endpointParam == "" {
			http.Error(w, "wikiric mockingbird: missing endpoint", http.StatusBadRequest)
			return
		}
		// Retrieve config for this endpoint
		config := db.GetMockingbirdConfigFromUserEndpoint(usrParam, endpointParam, method)
		if config == nil {
			http.Error(w, "wikiric mockingbird: unknown user or endpoint", http.StatusBadRequest)
			return
		}
		// duration := time.Since(timeStart)
		// fmt.Println(duration.Milliseconds())
		// #### HANDLE REQUEST ####
		var bodyContent []byte
		var err error
		if config.ResponseType == "message-same" {
			// We read the body here to avoid wasting time (we may not need it)
			bodyContent, err = io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "wikiric mockingbird: cannot read body", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", config.RequestContentType)
			w.WriteHeader(config.ResponseStatusCode)
			_, _ = fmt.Fprintln(w, string(bodyContent))
		} else if config.ResponseType == "message-fixed" {
			w.Header().Set("Content-Type", config.ResponseContentType)
			w.WriteHeader(config.ResponseStatusCode)
			_, _ = fmt.Fprintln(w, config.ResponseContent)
		}
		sendAnalytics(r, config, connector, bodyContent)
	}
}

func (db *GoDB) handleMockingbirdGet(connector *Connector, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// timeStart := time.Now()
		usrParam := chi.URLParam(r, "usr")
		if usrParam == "" {
			http.Error(w, "wikiric mockingbird: missing user", http.StatusBadRequest)
			return
		}
		endpointParam := chi.URLParam(r, "endpoint")
		if endpointParam == "" {
			http.Error(w, "wikiric mockingbird: missing endpoint", http.StatusBadRequest)
			return
		}
		// Retrieve config for this endpoint
		config := db.GetMockingbirdConfigFromUserEndpoint(usrParam, endpointParam, method)
		if config == nil {
			http.Error(w, "wikiric mockingbird: unknown user or endpoint", http.StatusBadRequest)
			return
		}
		// duration := time.Since(timeStart)
		// fmt.Println(duration.Milliseconds())
		// #### HANDLE REQUEST ####
		if config.ResponseType == "message-fixed" {
			w.Header().Set("Content-Type", config.ResponseContentType)
			w.WriteHeader(config.ResponseStatusCode)
			_, _ = fmt.Fprintln(w, config.ResponseContent)
		}
		sendAnalytics(r, config, connector, []byte{})
	}
}

func analyseRequest(r *http.Request, bodyContent []byte) *MockingBirdAnalytics {
	analytics := &MockingBirdAnalytics{}
	analytics.TimeCreated = TimeNowIsoString()
	if r == nil {
		return analytics
	}
	// Analyse header information
	if len(r.Header) > 0 {
		for name, values := range r.Header {
			analytics.RequestHeaders = append(analytics.RequestHeaders, RequestHeader{
				Name:  name,
				Value: strings.Join(values, ", "),
			})
		}
	}
	// Analyse Host Header (which gets put into its own field when being received)
	if r.Host != "" {
		analytics.RequestHeaders = append(analytics.RequestHeaders, RequestHeader{
			Name:  "Host",
			Value: r.Host,
		})
	}
	// Do we have a post body?
	if r.Body != nil && len(bodyContent) > 0 {
		analytics.RequestContent = string(bodyContent)
		analytics.RequestContentType = r.Header.Get("Content-Type")
	}
	// Is this an authorized request?
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Basic Auth?
		tmpUser, tmpPass, ok := r.BasicAuth()
		if ok {
			analytics.AuthorizationType = "Basic"
			analytics.AuthUser = tmpUser
			analytics.AuthPassword = tmpPass
		} else {
			// Bearer Token Auth?
			const prefix = "Bearer "
			if len(authHeader) >= len(prefix) && ascii.EqualFold([]byte(authHeader[:len(prefix)]), []byte(prefix)) {
				analytics.AuthorizationType = prefix
				analytics.AuthPassword = authHeader[len(prefix):]
			} else {
				// Digest Auth?
				const prefix = "Digest "
				if len(authHeader) >= len(prefix) && ascii.EqualFold([]byte(authHeader[:len(prefix)]), []byte(prefix)) {
					analytics.AuthorizationType = prefix
					analytics.AuthPassword = authHeader[len(prefix):]
				} else {
					// Fallback
					analytics.AuthorizationType = "(Unknown Authorization)"
					analytics.AuthPassword = authHeader
				}
			}
		}
	}
	// Return analysed request
	return analytics
}

func sendAnalytics(r *http.Request, config *MockingBirdConfigEntry, connector *Connector, bodyContent []byte) {
	analytics := analyseRequest(r, bodyContent)
	analytics.Endpoint = config.Endpoint
	analytics.ResponseType = config.ResponseType
	if config.ResponseType == "message-fixed" {
		analytics.ResponseContent = config.ResponseContent
	} else {
		analytics.ResponseContent = string(bodyContent)
	}
	analytics.RequestMethod = config.RequestMethod
	analyticsBytes, err := json.Marshal(analytics)
	if err != nil {
		return
	}
	// Now send a message via the connector
	connector.SessionsMu.RLock()
	session, ok := connector.Sessions.Get(config.Username)
	if !ok {
		connector.SessionsMu.RUnlock()
		return
	}
	cMSG := &ConnectorMsg{
		Type:          "[s:MOCKINGBIRD]",
		Action:        "inc_request",
		ReferenceUUID: "",
		Username:      "",
		Message:       string(analyticsBytes),
	}
	_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	connector.SessionsMu.RUnlock()
}

func (db *GoDB) handleMockingbirdConfigDelete() http.HandlerFunc {
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
		err = db.Delete(MockDB, mockID, []string{"usr-endpoint"})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}
