package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgraph-io/badger/v4"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

const StoreDB = "m11"

type Store struct {
	Name                 string          `json:"t"`
	Username             string          `json:"usr"`
	Description          string          `json:"desc"`
	Categories           []Category      `json:"cats"`
	TimeCreated          string          `json:"ts"`
	IsPrivate            bool            `json:"priv"`
	ParentUUID           string          `json:"pid"`
	ThumbnailURL         string          `json:"iurl"`
	ThumbnailAnimatedURL string          `json:"iurla"`
	BannerURL            string          `json:"burl"`
	BannerAnimatedURL    string          `json:"burla"`
	BankDetails          BankDetails     `json:"bank"`
	AnalyticsUUID        string          `json:"ana"` // Views, likes etc. will be stored in a separate database
	IsShiny              bool            `json:"shiny"`
	Appearance           StoreAppearance `json:"visual"`
	ItemCategories       []ItemCategory  `json:"icats"`
}

type ItemCategory struct {
	Name         string `json:"t"`
	Description  string `json:"desc"`
	ColorHex     string `json:"hex"`
	ThumbnailURL string `json:"iurl"`
	Type         string `json:"type"` // "cat" || "query"
	Value        string `json:"val"`
}

type StoreJourney struct {
	Name         string   `json:"t"`
	Description  string   `json:"desc"`
	StoreUUID    string   `json:"pid"`
	IsStart      bool     `json:"start"`
	TimeCreated  string   `json:"ts"`
	TimeUpdated  string   `json:"tsu"`
	ColorHex     string   `json:"hex"`
	ThumbnailURL string   `json:"iurl"`
	Optional     bool     `json:"opt"`
	NextUID      string   `json:"next"`
	PreviousUID  string   `json:"prev"`
	Categories   []string `json:"cats"`
	Query        string   `json:"query"`
	Brand        string   `json:"brand"`
	Colors       []string `json:"colors"`
	AmountItems  int      `json:"amt"` // Gets calculated by indexing
}

type StoreJourneyContainer struct {
	UUID string `json:"uid"`
	*StoreJourney
}

type StoreJourneyList struct {
	Journeys []*StoreJourneyContainer `json:"journeys"`
}

type BankDetails struct {
	Name      string `json:"name"`
	BankName  string `json:"bank"`
	IBAN      string `json:"iban"`
	SwiftCode string `json:"swift"`
}

type StoreEntry struct {
	UUID string `json:"uid"`
	*Store
	*Analytics
}

type StoreModification struct {
	Type     string `json:"type"`
	Field    string `json:"field"`
	OldValue string `json:"old"`
	NewValue string `json:"new"`
}

type StoreQuery struct {
	Query  string `json:"query"`
	Fields string `json:"fields"`
}

type StoreQueryResponse struct {
	Stores []StoreContainer `json:"stores"`
}

type StoreContainer struct {
	UUID string `json:"uid"`
	*Store
	*Analytics
	Accuracy float64 `json:"accuracy"`
}

type StoreAppearance struct {
	ImageBackgroundColor string `json:"imgBGColor"`
}

func (db *GoDB) PublicStoreEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	rapidDB *GoDB, connector *Connector, emailClient *EmailClient,
) {
	r.Route("/stores/public", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/order/{storeID}", db.handleStoreOrder(
			rapidDB, connector, emailClient))
		r.Post("/discover", db.handleStoreQuery(rapidDB))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/get/{storeID}", db.handleStoreVisit(rapidDB, false))
		r.Get("/usr/{storeID}", db.handleStoreVisit(rapidDB, true))
		// Journey Operations
		r.Route("/journey", func(r chi.Router) {
			r.Get("/get/{storeID}", db.handleStoreJourneyGet(rapidDB))
			r.Get("/discover/{journeyID}", db.handleStoreJourneyDiscover(rapidDB))
		})
	})
}

func (db *GoDB) ProtectedStoreEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	rapidDB *GoDB, connector *Connector,
) {
	r.Route("/stores/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/create", db.handleStoreCreate(rapidDB, connector))
		r.Post("/mod/{storeID}", db.handleStoreModification(rapidDB))
		r.Post("/cats/mod/{storeID}", db.handleStoreCategoryModification())
		// Journey Operations
		r.Route("/journey", func(r chi.Router) {
			r.Post("/create/{storeID}", db.handleStoreJourneyCreate(rapidDB))
			r.Post("/mod/{journeyID}", db.handleStoreJourneyModification(rapidDB))
			r.Post("/edit/{journeyID}", db.handleStoreJourneyEdit(rapidDB))
			// GET
			r.Get("/index/{storeID}", db.handleStoreJourneyIndex(rapidDB, connector))
			r.Get("/delete/{journeyID}", db.handleStoreJourneyDelete(rapidDB))
		})
		// ###########
		// ### GET ###
		// ###########
		r.Get("/get", db.handleStoreGet(rapidDB))
	})
}

func (a *Store) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	return nil
}

func (a *StoreModification) Bind(_ *http.Request) error {
	if a.Type == "" {
		return errors.New("missing type")
	}
	if a.Field == "" {
		return errors.New("missing field")
	}
	return nil
}

func (a *StoreQuery) Bind(_ *http.Request) error {
	if a.Query == "" {
		return errors.New("missing query")
	}
	return nil
}

func (a *ItemCategory) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	return nil
}

func (a *StoreJourney) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	if a.StoreUUID == "" {
		return errors.New("missing pid")
	}
	return nil
}

func (db *GoDB) handleStoreCreate(rapidDB *GoDB, connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Check if user has a store already
		resp, err := db.Select(StoreDB, map[string]string{
			"usr": FIndex(user.Username),
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
		// Retrieve POST payload
		request := &Store{}
		if err = render.Bind(r, request); err != nil {
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
		uUID, err := db.Insert(StoreDB, jsonEntry, map[string]string{
			"usr": FIndex(request.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
		// Notify *new* store owner! Yay!
		notification := &Notification{
			Title: fmt.Sprintf(
				"Hey, %s!", user.DisplayName),
			Description: fmt.Sprintf(
				"Your new store, %s, is up! Add items to be sold on it!", request.Name),
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

func (db *GoDB) handleStoreGet(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve user's store
		resp, err := db.Select(StoreDB, map[string]string{
			"usr": FIndex(user.Username),
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
		if len(response) < 1 {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err = json.Unmarshal(response[0].Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Is there an analytics entry?
		analytics := &Analytics{}
		if store.AnalyticsUUID != "" {
			anaBytes, txn := rapidDB.Get(AnaDB, store.AnalyticsUUID)
			if txn != nil {
				err = json.Unmarshal(anaBytes.Data, analytics)
				if err != nil {
					txn.Discard()
					analytics = &Analytics{}
				}
			}
		}
		render.JSON(w, r, &StoreEntry{
			Store:     store,
			UUID:      response[0].uUID,
			Analytics: analytics,
		})
	}
}

func (db *GoDB) handleStoreVisit(rapidDB *GoDB, user bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve store
		var response *EntryResponse
		var ok bool
		if !user {
			response, ok = db.Read(StoreDB, storeID)
		} else {
			ok = false
			resp, err := db.Select(StoreDB, map[string]string{
				"usr": FIndex(storeID),
			}, &SelectOptions{
				MaxResults: 1,
				Page:       0,
				Skip:       0,
			})
			if err == nil {
				tmp := <-resp
				if len(tmp) > 0 {
					response = tmp[0]
					storeID = response.uUID
					ok = true
				}
			}
		}
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err := json.Unmarshal(response.Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		render.JSON(w, r, &StoreEntry{
			Store: store,
			UUID:  response.uUID,
		})
		// Is there an analytics entry?
		analytics := &Analytics{}
		if store.AnalyticsUUID != "" {
			anaBytes, txn := rapidDB.Get(AnaDB, store.AnalyticsUUID)
			if txn != nil {
				err = json.Unmarshal(anaBytes.Data, analytics)
				if err != nil {
					txn.Discard()
					analytics = &Analytics{}
				} else {
					analytics.Views += 1
					// Asynchronously update view count in database
					go func() {
						defer txn.Discard()
						jsonAna, err := json.Marshal(analytics)
						if err == nil {
							_ = rapidDB.Update(AnaDB, txn, store.AnalyticsUUID, jsonAna, map[string]string{})
						}
					}()
				}
			}
		} else {
			// Create an analytics entry to keep track of the views
			analytics = &Analytics{}
			analytics.Views = 1
			jsonAna, err := json.Marshal(analytics)
			if err == nil {
				// Insert analytics while returning its UUID to the store for reference
				storeBytes, txnWis := db.Get(StoreDB, storeID)
				defer txnWis.Discard()
				store.AnalyticsUUID, err = rapidDB.Insert(AnaDB, jsonAna, map[string]string{})
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				// Update store
				storeJson, err := json.Marshal(store)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(StoreDB, txnWis, storeBytes.uUID, storeJson, map[string]string{
					"usr": FIndex(store.Username),
				})
			}
		}
	}
}

func (db *GoDB) handleStoreCategoryModification() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Check if the category should be deleted
		doDeleteTmp := r.URL.Query().Get("del")
		doDelete := false
		if doDeleteTmp != "" {
			if doDeleteTmp == "true" {
				doDelete = true
			}
		}
		// Retrieve POST payload
		request := &Category{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve store
		response, txn := db.Get(StoreDB, storeID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		store := &Store{}
		err := json.Unmarshal(response.Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if role is present
		index := -1
		for ix, role := range store.Categories {
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
			store.Categories = append(store.Categories[:index], store.Categories[index+1:]...)
		} else {
			// Did it exist yet?
			if index == -1 {
				store.Categories = append(store.Categories, *request)
			} else {
				store.Categories[index] = *request
			}
		}
		jsonEntry, err := json.Marshal(store)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(StoreDB, txn, response.uUID, jsonEntry, map[string]string{
			"usr": FIndex(store.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleStoreModification(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &StoreModification{}
		var err error
		if err = render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok := db.Read(StoreDB, storeID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err = json.Unmarshal(response.Data, store)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != store.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Check what action is required
		if request.Type == "edit" {
			if request.Field == "iurl" {
				err = db.changeStoreImage(rapidDB, user, storeID, request, false, false)
			} else if request.Field == "burl" {
				err = db.changeStoreImage(rapidDB, user, storeID, request, true, false)
			} else if request.Field == "bank" {
				err = db.changeStoreBankDetails(user, storeID, request)
			} else if request.Field == "shiny" {
				err = db.changeStoreAppearance(user, storeID, request, "shiny")
			}
		}
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
}

func (db *GoDB) changeStoreBankDetails(
	user *User, storeID string, request *StoreModification,
) error {
	// Retrieve store
	response, txn := db.Get(StoreDB, storeID)
	if txn == nil {
		return nil
	}
	defer txn.Discard()
	store := &Store{}
	err := json.Unmarshal(response.Data, store)
	if err != nil {
		return err
	}
	// Check rights
	if store.Username != user.Username {
		return errors.New("forbidden")
	}
	// Get new bank details
	bank := &BankDetails{}
	err = json.Unmarshal([]byte(request.NewValue), bank)
	if err != nil {
		return err
	}
	store.BankDetails = *bank
	// Save
	jsonEntry, err := json.Marshal(store)
	if err != nil {
		return err
	}
	err = db.Update(StoreDB, txn, response.uUID, jsonEntry, map[string]string{
		"usr": FIndex(store.Username),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) changeStoreAppearance(
	user *User, storeID string, request *StoreModification, appearance string,
) error {
	// Retrieve store
	response, txn := db.Get(StoreDB, storeID)
	if txn == nil {
		return nil
	}
	defer txn.Discard()
	store := &Store{}
	err := json.Unmarshal(response.Data, store)
	if err != nil {
		return err
	}
	// Check rights
	if store.Username != user.Username {
		return errors.New("forbidden")
	}
	if request.NewValue == "true" {
		store.IsShiny = true
	} else {
		store.IsShiny = false
	}
	// Save
	jsonEntry, err := json.Marshal(store)
	if err != nil {
		return err
	}
	err = db.Update(StoreDB, txn, response.uUID, jsonEntry, map[string]string{
		"usr": FIndex(store.Username),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) changeStoreImage(
	rapidDB *GoDB, user *User, storeID string, request *StoreModification, isBanner, isAnimated bool,
) error {
	if request.NewValue == "" {
		return nil
	}
	// Check file size
	fileSize := GetBase64BinaryLength(request.NewValue)
	if fileSize > 20*MiB {
		return nil
	}
	var filename string
	// Construct filename
	if isBanner {
		filename = "banner-store"
	} else {
		filename = "thumbnail-store"
	}
	// Save image
	fileRequest := &FileSubmission{
		DataBase64: request.NewValue,
		Filename:   filename,
		IsPrivate:  false,
	}
	fileSizeMB := float64(fileSize) / float64(1*MiB)
	uUID, err := rapidDB.SaveBase64AsFile(user, fileRequest, fileSizeMB)
	if err != nil {
		return err
	}
	// Retrieve store
	response, txn := db.Get(StoreDB, storeID)
	if txn == nil {
		return nil
	}
	defer txn.Discard()
	store := &Store{}
	err = json.Unmarshal(response.Data, store)
	if err != nil {
		return err
	}
	// Check rights
	if store.Username != user.Username {
		return errors.New("forbidden")
	}
	// Set image url
	if isBanner {
		store.BannerURL = fmt.Sprintf("files/public/get/%s", uUID)
	} else {
		store.ThumbnailURL = fmt.Sprintf("files/public/get/%s", uUID)
	}
	// Save
	jsonEntry, err := json.Marshal(store)
	if err != nil {
		return err
	}
	err = db.Update(StoreDB, txn, response.uUID, jsonEntry, map[string]string{
		"usr": FIndex(store.Username),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) handleStoreOrder(rapidDB *GoDB,
	connector *Connector, emailClient *EmailClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// We do not retrieve the user as usual since this is an unauthorized endpoint
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &Order{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve store
		var ok bool
		storeResp, ok := db.Read(StoreDB, storeID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err := json.Unmarshal(storeResp.Data, store)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Sanitize
		// request.Username = user.Username
		request.StoreUUID = storeID
		request.TimeCreated = TimeToIsoString(time.Now().UTC())
		request.State = OrderStateOpen
		request.BillingState = OrderBillingStateOpen
		request.DeliveryState = OrderDeliveryStateOpen
		request.BillingHistory = make([]BillingEntry, 0)
		var vars map[string]string
		var varVars map[string]string
		for _, item := range request.ItemPositions {
			if item.Variations == nil {
				item.Variations = make([]ItemVariation, 0)
			} else {
				// Check if there are duplicate variations
				// TODO: Also check if mandatory variations are missing
				vars = map[string]string{}
				for _, variation := range item.Variations {
					if vars[variation.Name] != "" {
						http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
						return
					}
					vars[variation.Name] = "x"
					// Check if there are duplicate variation variations
					varVars = map[string]string{}
					for _, varVar := range variation.Variations {
						if varVars[varVar.StringValue] != "" {
							http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
							return
						}
						varVars[varVar.StringValue] = "x"
					}
				}
			}
		}
		// Calculate
		err = CalculateOrder(rapidDB, request, true)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Save order and notify buyer and shop owner
		orderJson, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := rapidDB.Insert(OrderDB, orderJson, map[string]string{
			"usr":       FIndex(request.Username),
			"pid-state": fmt.Sprintf("%s;%s", request.StoreUUID, request.State),
		})
		// Respond
		_, _ = fmt.Fprintln(w, uUID)
		go func() {
			// Notify buyer
			err = NotifyBuyerOrderConfirmation(
				store, request, uUID, rapidDB, connector, emailClient)
			// Notify store owner
			err = db.NotifyStoreOwnerOrderConfirmation(
				store, request, uUID, rapidDB, connector, emailClient)
		}()
	}
}

func (db *GoDB) handleStoreQuery(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// We do not retrieve the user as usual since this is an unauthorized endpoint
		// Retrieve POST payload
		request := &StoreQuery{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Get all stores
		resp, err := db.Select(StoreDB, map[string]string{
			"usr": "",
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Prepare response
		storeList := StoreQueryResponse{make([]StoreContainer, 0)}
		response := <-resp
		if len(response) < 1 {
			render.JSON(w, r, storeList)
			return
		}
		// Iterate over all items found
		var store *Store
		var analytics *Analytics
		var container *StoreContainer
		var points int64
		var accuracy float64
		b := false
		// Turn query text into a full regex pattern
		words, p := GetRegexQuery(request.Query)
		for _, entry := range response {
			store = &Store{}
			err = json.Unmarshal(entry.Data, store)
			if err != nil {
				continue
			}
			// Flip boolean on each iteration
			b = !b
			accuracy, points = GetStoreQueryPoints(store, request, p, words, b)
			if points <= 0 {
				continue
			}
			// Load analytics if available
			analytics = &Analytics{}
			if store.AnalyticsUUID != "" {
				anaBytes, okAna := rapidDB.Read(AnaDB, store.AnalyticsUUID)
				if okAna {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						analytics = &Analytics{}
					}
				}
			}
			container = &StoreContainer{
				UUID:      entry.uUID,
				Store:     store,
				Analytics: analytics,
				Accuracy:  accuracy,
			}
			storeList.Stores = append(storeList.Stores, *container)
		}
		// Sort entries by accuracy
		if len(storeList.Stores) > 1 {
			sort.SliceStable(
				storeList.Stores, func(i, j int) bool {
					return storeList.Stores[i].Accuracy > storeList.Stores[j].Accuracy
				},
			)
		}
		render.JSON(w, r, storeList)
	}
}

func GetStoreQueryPoints(
	store *Store, query *StoreQuery, p *regexp.Regexp, words map[string]*QueryWord, b bool,
) (float64, int64) {
	// Get all matches in selected fields
	var mName, mDesc, mUser []string
	if query.Fields == "" || strings.Contains(query.Fields, "title") {
		mName = p.FindAllString(store.Name, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "desc") {
		mDesc = p.FindAllString(store.Description, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "usr") {
		mUser = p.FindAllString(store.Username, -1)
	}
	if len(mName) < 1 && len(mDesc) < 1 && len(mUser) < 1 {
		// Return 0 if there were no matches
		return 0.0, 0
	}
	// Clean up
	for _, word := range words {
		word.B = !b
	}
	// Calculate points
	points := int64(0)
	pointsMax := len(words)
	accuracy := 0.0
	for _, word := range mName {
		if words[strings.ToLower(word)] != nil {
			words[strings.ToLower(word)].B = b
		} else {
			words[strings.ToLower(word)] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
	for _, word := range mDesc {
		if words[strings.ToLower(word)] != nil {
			words[strings.ToLower(word)].B = b
		} else {
			words[strings.ToLower(word)] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
	for _, word := range mUser {
		if words[strings.ToLower(word)] != nil {
			words[strings.ToLower(word)].B = b
		} else {
			words[strings.ToLower(word)] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
	// How many words were matched?
	for _, word := range words {
		if word.B == b {
			points += word.Points
		}
	}
	accuracy = float64(points) / float64(pointsMax)
	return accuracy, points
}

func (db *GoDB) handleStoreJourneyCreate(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Read(StoreDB, storeID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err := json.Unmarshal(response.Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &StoreJourney{}
		if err = render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Sanitize
		request.TimeCreated = TimeNowIsoString()
		// We're at the start if there is no journey entry before this one (duh!)
		request.IsStart = request.PreviousUID == ""
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Construct indices if we're at the start!
		indices := map[string]string{}
		if request.IsStart {
			indices["pid-jny"] = FIndex(request.StoreUUID)
		}
		uUID, err := rapidDB.Insert(StoreDB, jsonEntry, indices)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleStoreJourneyModification(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// What is supposed to happen?
		modType := r.URL.Query().Get("modtype")
		if modType == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// The following code will repeat link and unlink a lot since it assumes a future implementation
		// ...of more features as those two. Now stop looking at this comment. Thanks.
		if modType != "link" && modType != "unlink" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		dirType := ""
		if modType == "link" || modType == "unlink" {
			dirType = r.URL.Query().Get("dirtype")
			if dirType == "" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			if dirType != "next" && dirType != "prev" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		}
		// Retrieve journey that is about to be modified
		journeyID := chi.URLParam(r, "journeyID")
		if journeyID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		var response *EntryResponse
		var ok bool
		response, ok = rapidDB.Read(StoreDB, journeyID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		other := &StoreJourney{}
		err := json.Unmarshal(response.Data, other)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user is the owner
		response, ok = db.Read(StoreDB, other.StoreUUID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err = json.Unmarshal(response.Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// If we (un)link, we need to remove the entry that is currently linked
		if modType == "link" || modType == "unlink" {
			uid := ""
			if dirType == "next" {
				uid = other.NextUID
			} else if dirType == "prev" {
				uid = other.PreviousUID
			}
			if uid != "" {
				err = rapidDB.Delete(StoreDB, uid, []string{"pid-jny"})
				if err != nil {
					fmt.Println(err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
			}
		}
		// If unlinking was everything, we quit
		if modType == "unlink" {
			return
		}
		if modType == "link" {
			// Retrieve POST payload
			request := &StoreJourney{}
			if err = render.Bind(r, request); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Retrieve other journey once again (now with a transaction!)
			var txnOther *badger.Txn
			response, txnOther = rapidDB.Get(StoreDB, journeyID)
			if txnOther == nil {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			other = &StoreJourney{}
			err = json.Unmarshal(response.Data, other)
			if err != nil {
				fmt.Println(err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Link this journey to the other, but flipped
			// When we modify the others next, it will be the prev for the request journey
			if dirType == "next" {
				request.PreviousUID = journeyID
			} else if dirType == "prev" {
				request.NextUID = journeyID
			}
			// Sanitize
			request.IsStart = request.PreviousUID == ""
			// Store request journey
			var jsonEntry []byte
			jsonEntry, err = json.Marshal(request)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			var uUID string
			indices := map[string]string{}
			if request.IsStart {
				indices["pid-jny"] = FIndex(request.StoreUUID)
			}
			uUID, err = rapidDB.Insert(StoreDB, jsonEntry, indices)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Also link the other
			if dirType == "next" {
				other.NextUID = uUID
			} else if dirType == "prev" {
				other.PreviousUID = uUID
			}
			// Sanitize
			other.IsStart = other.PreviousUID == ""
			// Also update other journey
			jsonEntry, err = json.Marshal(other)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Remove index if this journey entry is not at the start anymore
			indices = map[string]string{}
			if other.IsStart {
				indices["pid-jny"] = FIndex(request.StoreUUID)
			} else {
				indices["pid-jny"] = ""
			}
			err = rapidDB.Update(StoreDB, txnOther, journeyID, jsonEntry, indices)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			_, _ = fmt.Fprintln(w, uUID)
		}
	}
}

func (db *GoDB) handleStoreJourneyEdit(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve journey that is about to be edited
		journeyID := chi.URLParam(r, "journeyID")
		if journeyID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		var response *EntryResponse
		var ok bool
		response, ok = rapidDB.Read(StoreDB, journeyID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		journey := &StoreJourney{}
		err := json.Unmarshal(response.Data, journey)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user is the owner
		response, ok = db.Read(StoreDB, journey.StoreUUID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err = json.Unmarshal(response.Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		txnOther := rapidDB.NewTransaction(true)
		// Retrieve POST payload
		request := &StoreJourney{}
		if err = render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Remove index if this journey entry is not at the start anymore
		request.IsStart = request.PreviousUID == ""
		indices := map[string]string{}
		if request.IsStart {
			indices["pid-jny"] = FIndex(request.StoreUUID)
		} else {
			indices["pid-jny"] = ""
		}
		// Override the journey
		var jsonEntry []byte
		jsonEntry, err = json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = rapidDB.Update(StoreDB, txnOther, journeyID, jsonEntry, indices)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleStoreJourneyGet(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		journeys := StoreJourneyList{Journeys: make([]*StoreJourneyContainer, 0)}
		// Retrieve store journeys
		resp, cancel, err := rapidDB.SSelect(StoreDB, map[string]string{
			"pid-jny": FIndex(storeID),
		}, nil, 10, 1, true, false)
		defer cancel()
		if err != nil {
			render.JSON(w, r, journeys)
			return
		}
		var journey *StoreJourney
		for entry := range resp {
			journey = &StoreJourney{}
			err = json.Unmarshal(entry.Data, journey)
			if err != nil {
				continue
			}
			journeys.Journeys = append(journeys.Journeys, &StoreJourneyContainer{
				UUID:         entry.uUID,
				StoreJourney: journey,
			})
		}
		render.JSON(w, r, journeys)
	}
}

func (db *GoDB) handleStoreJourneyIndex(rapidDB *GoDB, connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Check if user has access to the store
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Read(StoreDB, storeID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err := json.Unmarshal(response.Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve connector entry of requester, so we can inform them about the progress!
		connector.SessionsMu.RLock()
		sesh, hasSesh := connector.Sessions.Get(user.Username)
		connector.SessionsMu.RUnlock()
		if hasSesh {
			_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
				Type:          "[s:storeix]",
				Action:        "log",
				ReferenceUUID: "",
				Username:      user.Username,
				Message:       fmt.Sprint("m11Stores >>> (1/2) Retrieving store journeys"),
			})
		}
		// Retrieve store journeys
		resp, cancel, err := rapidDB.SSelect(StoreDB, map[string]string{
			"pid-jny": FIndex(storeID),
		}, nil, 10, 1, true, false)
		defer cancel()
		if err != nil {
			if hasSesh {
				_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
					Type:          "[s:storeix]",
					Action:        "log",
					ReferenceUUID: "",
					Username:      user.Username,
					Message:       fmt.Sprint("m11Stores >>> Cancelled due to an error: ", err.Error()),
				})
			}
			return
		}
		if hasSesh {
			_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
				Type:          "[s:storeix]",
				Action:        "log",
				ReferenceUUID: "",
				Username:      user.Username,
				Message:       fmt.Sprint("m11Stores >>> (1/2) DONE"),
			})
			_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
				Type:          "[s:storeix]",
				Action:        "log",
				ReferenceUUID: "",
				Username:      user.Username,
				Message:       fmt.Sprint("m11Stores >>> (2/2) Updating store journeys..."),
			})
		}
		var journey *StoreJourney
		var index map[string]string
		var words map[string]*QueryWord
		var points int
		var cnts *MassEntryResponse
		var offerCount int
		var jsonEntry []byte
		var wrds []string
		var ixEntry []byte
		var customIndices bool
		for entry := range resp {
			journey = &StoreJourney{}
			err = json.Unmarshal(entry.Data, journey)
			if err != nil || (journey.Query == "" && len(journey.Categories) < 1 && journey.Brand == "") {
				continue
			}
			// Get all items matching the journey's criteria!
			// Retrieve all Item entries respecting the query index filters
			customIndices = false
			index = map[string]string{}
			if journey.Brand != "" {
				index["pid-brand"] =
					fmt.Sprintf("%s;%s", storeID, strings.ToLower(journey.Brand))
				customIndices = true
			}
			if len(journey.Categories) > 0 {
				for i, category := range journey.Categories {
					journey.Categories[i] = strings.ToLower(category)
					index[fmt.Sprintf("pid-cat[%d", i)] =
						fmt.Sprintf("%s;%s;", storeID, journey.Categories[i])
				}
				customIndices = true
			}
			if len(journey.Colors) > 0 {
				for i, color := range journey.Colors {
					index[fmt.Sprintf("pid-clrs[%d", i)] =
						fmt.Sprintf("%s;%s;", storeID, strings.ToLower(color))
				}
				customIndices = true
			}
			if journey.Brand != "" {
				journey.Brand = strings.ToLower(journey.Brand)
			}
			// If there would be no indices, we simply continue with the next journey
			// ...as it is pointless to go through all offers for each journey
			if !customIndices {
				continue
			}
			if journey.Query != "" {
				words, _ = GetRegexQuery(journey.Query)
				for wr := range words {
					wrds = append(wrds, wr)
				}
			}
			// Iterate over all items found
			responseT, cancelT, errT := rapidDB.SSelect(ItemDB, index, nil,
				30, 1, true, false,
			)
			if errT != nil {
				cancelT()
				continue
			}
			offerCount = 0
			for entryT := range responseT {
				if journey.Query == "" {
					offerCount += 1
					continue
				}
				points = 0
				ixEntry = entryT.Data
				cnts = SearchInBytes(ixEntry, "t", wrds, 100)
				if cnts != nil && len(cnts.Counts) > 0 {
					for _, wCount := range cnts.Counts {
						points += len(wCount)
					}
					if points <= 0 {
						continue
					}
				}
				ixEntry = entryT.Data
				cnts = SearchInBytes(ixEntry, "desc", wrds, 200)
				if cnts != nil && len(cnts.Counts) > 0 {
					for _, wCount := range cnts.Counts {
						points += len(wCount)
					}
				}
				ixEntry = entryT.Data
				cnts = SearchInBytes(ixEntry, "keys", wrds, 100)
				if cnts != nil && len(cnts.Counts) > 0 {
					for _, wCount := range cnts.Counts {
						points += len(wCount)
					}
				}
				if points > 0 {
					offerCount += 1
				}
			}
			if offerCount < 1 {
				continue
			}
			// Update the journey's offer count
			jny, txn := rapidDB.Get(StoreDB, entry.uUID)
			journey = &StoreJourney{}
			err = json.Unmarshal(jny.Data, journey)
			if err != nil {
				txn.Discard()
				continue
			}
			journey.AmountItems = offerCount
			journey.TimeUpdated = TimeNowIsoString()
			jsonEntry, err = json.Marshal(journey)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = rapidDB.Update(StoreDB, txn, entry.uUID, jsonEntry, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			timer := time.NewTimer(time.Millisecond * 500)
			<-timer.C
			if hasSesh {
				_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
					Type:          "[s:storeix]",
					Action:        "log",
					ReferenceUUID: "",
					Username:      user.Username,
					Message:       fmt.Sprint("m11Stores >>> (2/2) Set ", offerCount, " offers for ", journey.Name),
				})
			}
		}
		// We are done!
		connector.SessionsMu.RLock()
		sesh, hasSesh = connector.Sessions.Get(user.Username)
		connector.SessionsMu.RUnlock()
		if hasSesh {
			_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
				Type:          "[s:storeix]",
				Action:        "log",
				ReferenceUUID: "",
				Username:      user.Username,
				Message:       fmt.Sprint("m11Stores >>> (2/2) DONE"),
			})
		}
	}
}

func (db *GoDB) handleStoreJourneyDiscover(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Retrieve journey that is marking the beginning of our discovery
		journeyID := chi.URLParam(r, "journeyID")
		if journeyID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		var response *EntryResponse
		var ok bool
		response, ok = rapidDB.Read(StoreDB, journeyID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		list := StoreJourneyList{Journeys: make([]*StoreJourneyContainer, 0)}
		journey := &StoreJourney{}
		err := json.Unmarshal(response.Data, journey)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		list.Journeys = append(list.Journeys, &StoreJourneyContainer{
			UUID:         response.uUID,
			StoreJourney: journey,
		})
		// Store journey are double linked lists, so we will retrieve journey entries until there is no <next> uuid
		for {
			if journey.NextUID == "" {
				render.JSON(w, r, list)
				return
			}
			response, ok = rapidDB.Read(StoreDB, journey.NextUID)
			if !ok {
				render.JSON(w, r, list)
				return
			}
			// We override our current journey since we are in a loop!
			journey = &StoreJourney{}
			err = json.Unmarshal(response.Data, journey)
			if err != nil {
				// We would not be able to retrieve more journeys, so we need to stop here...
				render.JSON(w, r, list)
				return
			}
			list.Journeys = append(list.Journeys, &StoreJourneyContainer{
				UUID:         response.uUID,
				StoreJourney: journey,
			})
		}
	}
}

func (db *GoDB) handleStoreJourneyDelete(rapidDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve journey that is about to be deleted
		journeyID := chi.URLParam(r, "journeyID")
		if journeyID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		var response *EntryResponse
		var ok bool
		response, ok = rapidDB.Read(StoreDB, journeyID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		journey := &StoreJourney{}
		err := json.Unmarshal(response.Data, journey)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user is the owner
		response, ok = db.Read(StoreDB, journey.StoreUUID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err = json.Unmarshal(response.Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Do we have to re-link journey entries?
		// If there is a previous and next one for example, we will join them
		hasPrev := false
		hasNext := false
		var prev *StoreJourney
		var next *StoreJourney
		var responsePrev, responseNext *EntryResponse
		var txnPrev, txnNext *badger.Txn
		if journey.PreviousUID != "" {
			responsePrev, txnPrev = rapidDB.Get(StoreDB, journey.PreviousUID)
			if txnPrev != nil {
				prev = &StoreJourney{}
				err = json.Unmarshal(responsePrev.Data, prev)
				if err == nil {
					hasPrev = true
				}
			}
		}
		if journey.NextUID != "" {
			responseNext, txnNext = rapidDB.Get(StoreDB, journey.NextUID)
			if txnNext != nil {
				next = &StoreJourney{}
				err = json.Unmarshal(responseNext.Data, next)
				if err == nil {
					hasNext = true
				}
			}
		}
		if hasPrev && hasNext {
			// Join the two entries
			prev.NextUID = responseNext.uUID
			next.PreviousUID = responsePrev.uUID
		} else {
			// Clear the UUID instead
			if hasPrev {
				prev.NextUID = ""
			} else if hasNext {
				next.PreviousUID = ""
			}
		}
		// Save the entries
		var jsonEntry []byte
		var indices map[string]string
		if hasPrev {
			prev.IsStart = prev.PreviousUID == ""
			indices = map[string]string{}
			if prev.IsStart {
				indices["pid-jny"] = FIndex(journey.StoreUUID)
			} else {
				indices["pid-jny"] = ""
			}
			jsonEntry, err = json.Marshal(prev)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = rapidDB.Update(StoreDB, txnPrev, responsePrev.uUID, jsonEntry, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		if hasNext {
			next.IsStart = next.PreviousUID == ""
			indices = map[string]string{}
			if next.IsStart {
				indices["pid-jny"] = FIndex(journey.StoreUUID)
			} else {
				indices["pid-jny"] = ""
			}
			jsonEntry, err = json.Marshal(next)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = rapidDB.Update(StoreDB, txnNext, responseNext.uUID, jsonEntry, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		// Finally, delete the journey that was targeted
		err = rapidDB.Delete(StoreDB, journeyID, []string{"pid-jny"})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}
