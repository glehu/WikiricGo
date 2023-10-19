package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
	"time"
)

type Store struct {
	Name                 string      `json:"t"`
	Username             string      `json:"usr"`
	Description          string      `json:"desc"`
	Categories           []Category  `json:"cats"`
	TimeCreated          string      `json:"ts"`
	IsPrivate            bool        `json:"priv"`
	ParentUUID           string      `json:"pid"`
	ThumbnailURL         string      `json:"iurl"`
	ThumbnailAnimatedURL string      `json:"iurla"`
	BannerURL            string      `json:"burl"`
	BannerAnimatedURL    string      `json:"burla"`
	BankDetails          BankDetails `json:"bank"`
	AnalyticsUUID        string      `json:"ana"` // Views, likes etc. will be stored in a separate database
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
}

type StoreModification struct {
	Type     string `json:"type"`
	Field    string `json:"field"`
	OldValue string `json:"old"`
	NewValue string `json:"new"`
}

func OpenStoresDatabase() *GoDB {
	db := OpenDB("stores")
	return db
}

func (db *GoDB) PublicStoreEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	itemDB, orderDB, notificationDB, analyticsDB *GoDB, connector *Connector, emailClient *EmailClient,
) {
	r.Route("/stores/public", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/order/{storeID}", db.handleStoreOrder(
			itemDB, orderDB, notificationDB, analyticsDB, connector, emailClient))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/get/{storeID}", db.handleStoreVisit(analyticsDB))
	})
}

func (db *GoDB) ProtectedStoreEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	userDB, notificationDB, filesDB *GoDB, connector *Connector,
) {
	r.Route("/stores/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/create", db.handleStoreCreate(notificationDB, connector))
		r.Post("/mod/{storeID}", db.handleStoreModification(filesDB))
		r.Post("/cats/mod/{storeID}", db.handleStoreCategoryModification())
		// ###########
		// ### GET ###
		// ###########
		r.Get("/get", db.handleStoreGet())
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

func (db *GoDB) handleStoreCreate(notificationDB *GoDB, connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Check if user has a store already
		resp, err := db.Select(map[string]string{
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
		uUID, err := db.Insert(jsonEntry, map[string]string{
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
			_, _ = notificationDB.Insert(jsonNotification, map[string]string{
				"usr": FIndex(request.Username),
			})
		}
	}
}

func (db *GoDB) handleStoreGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve user's store
		resp, err := db.Select(map[string]string{
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
		render.JSON(w, r, &StoreEntry{
			Store: store,
			UUID:  response[0].uUID,
		})
	}
}

func (db *GoDB) handleStoreVisit(analyticsDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve store
		response, ok := db.Read(storeID)
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
			UUID:  storeID,
		})
		// Is there an analytics entry?
		analytics := &Analytics{}
		if store.AnalyticsUUID != "" {
			anaBytes, txn := analyticsDB.Get(store.AnalyticsUUID)
			if txn != nil {
				err := json.Unmarshal(anaBytes.Data, analytics)
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
							_ = analyticsDB.Update(txn, store.AnalyticsUUID, jsonAna, map[string]string{})
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
				storeBytes, txnWis := db.Get(storeID)
				defer txnWis.Discard()
				store.AnalyticsUUID, err = analyticsDB.Insert(jsonAna, map[string]string{})
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
				err = db.Update(txnWis, storeBytes.uUID, storeJson, map[string]string{
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
		response, txn := db.Get(storeID)
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
		err = db.Update(txn, response.uUID, jsonEntry, map[string]string{
			"usr": FIndex(store.Username),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleStoreModification(filesDB *GoDB) http.HandlerFunc {
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
		response, ok := db.Read(storeID)
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
				err = db.changeStoreImage(filesDB, user, storeID, request, false, false)
			} else if request.Field == "burl" {
				err = db.changeStoreImage(filesDB, user, storeID, request, true, false)
			} else if request.Field == "bank" {
				err = db.changeStoreBankDetails(user, storeID, request)
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
	response, txn := db.Get(storeID)
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
	err = db.Update(txn, response.uUID, jsonEntry, map[string]string{
		"usr": FIndex(store.Username),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) changeStoreImage(
	filesDB *GoDB, user *User, storeID string, request *StoreModification, isBanner, isAnimated bool,
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
		filename = "banner-chat"
	} else {
		filename = "thumbnail-chat"
	}
	// Save image
	fileRequest := &FileSubmission{
		DataBase64: request.NewValue,
		Filename:   filename,
		IsPrivate:  false,
	}
	fileSizeMB := float64(fileSize) / float64(1*MiB)
	uUID, err := filesDB.SaveBase64AsFile(user, fileRequest, fileSizeMB)
	if err != nil {
		return err
	}
	// Retrieve store
	response, txn := db.Get(storeID)
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
	err = db.Update(txn, response.uUID, jsonEntry, map[string]string{
		"usr": FIndex(store.Username),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) handleStoreOrder(itemDB, orderDB, notificationDB, analyticsDB *GoDB,
	connector *Connector, emailClient *EmailClient,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// We do not retrieve the user as usual since this is an unauthorized endpoint
		// Retrieve POST payload
		request := &Order{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve store
		var ok bool
		storeResp, ok := db.Read(request.StoreUUID)
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
		err = CalculateOrder(itemDB, request, true)
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
		uUID, err := orderDB.Insert(orderJson, map[string]string{
			"usr": FIndex(request.Username),
			"pid": request.StoreUUID,
		})
		// Respond
		_, _ = fmt.Fprintln(w, uUID)
		// Notify buyer
		err = NotifyBuyerOrderConfirmation(
			store, request, uUID, notificationDB, connector, emailClient)
		// Notify store owner
		err = NotifyStoreOwnerOrderConfirmation(
			store, request, uUID, notificationDB, connector, emailClient)
	}
}
