package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Item struct {
	Name                  string          `json:"t"`
	Description           string          `json:"desc"`
	Keywords              string          `json:"keys"`
	Attributes            []ItemAttribute `json:"attr"`
	Categories            []string        `json:"cats"`
	Variations            []ItemVariation `json:"vars"`
	Colors                []Category      `json:"clrs"`
	NetPrice              float64         `json:"net"`
	VATPercent            float64         `json:"vatp"`
	Unit                  string          `json:"unit"`
	TimeCreated           string          `json:"ts"`
	StoreUUID             string          `json:"pid"`
	ThumbnailURLs         []ItemImage     `json:"iurls"`
	ThumbnailAnimatedURLs []ItemImage     `json:"iurlas"`
	BannerURLs            []ItemImage     `json:"burls"`
	BannerAnimatedURLs    []ItemImage     `json:"burlas"`
	AnalyticsUUID         string          `json:"ana"` // Views, likes etc. will be stored in a separate database
}

type ItemEntry struct {
	UUID string `json:"uid"`
	*Item
}

type ItemContainer struct {
	UUID string `json:"uid"`
	*Item
	*Analytics
	Accuracy float64 `json:"accuracy"`
}

type ItemAttribute struct {
	Name        string  `json:"t"`
	Description string  `json:"desc"`
	NumberValue float64 `json:"nval"`
	StringValue string  `json:"sval"`
	Unit        string  `json:"unit"`
	Type        string  `json:"type"`
}

type ItemVariation struct {
	Name        string               `json:"t"`
	Description string               `json:"desc"`
	Variations  []ItemVariationEntry `json:"vars"`
}

type ItemVariationEntry struct {
	Description string  `json:"desc"`
	NumberValue float64 `json:"nval"`
	StringValue string  `json:"sval"`
	NetPrice    float64 `json:"net"`
}

type ItemImage struct {
	URL     string `json:"url"`
	Caption string `json:"t"`
}

type ItemQuery struct {
	Query  string `json:"query"`
	Type   string `json:"type"`
	Fields string `json:"fields"`
	State  string `json:"state"`
}

type ItemQueryResponse struct {
	TimeSeconds float64          `json:"respTime"`
	Items       []*ItemContainer `json:"items"`
}

type ItemModification struct {
	Type      string `json:"type"`
	Field     string `json:"field"`
	OldValue  string `json:"old"`
	NewValue  string `json:"new"`
	MetaValue string `json:"meta"`
}

func OpenItemsDatabase() *GoDB {
	db := OpenDB("items")
	return db
}

func (db *GoDB) PublicItemsEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth, storeDB, analyticsDB *GoDB) {
	r.Route("/items/public", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/query/{storeID}", db.handleItemQuery(storeDB, analyticsDB))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/get/{itemID}", db.handleItemGet(analyticsDB))
	})
}

func (db *GoDB) ProtectedItemEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	storeDB, userDB, notificationDB, analyticsDB, filesDB *GoDB,
) {
	r.Route("/items/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/create/{storeID}", db.handleItemCreate(storeDB, filesDB))
		r.Post("/edit/{itemID}", db.handleItemEdit(storeDB, filesDB))
		r.Post("/mod/{itemID}", db.handleItemModification(storeDB, filesDB))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/delete/{itemID}", db.handleItemDelete(storeDB, analyticsDB))
	})
}

func (a *Item) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	if a.Description == "" {
		return errors.New("missing desc")
	}
	return nil
}

func (a *ItemQuery) Bind(_ *http.Request) error {
	if a.Query == "" {
		return errors.New("missing query")
	}
	return nil
}

func (a *ItemModification) Bind(_ *http.Request) error {
	if a.Type == "" {
		return errors.New("missing type")
	}
	if a.Field == "" {
		return errors.New("missing field")
	}
	return nil
}

func (db *GoDB) handleItemCreate(storeDB, filesDB *GoDB) http.HandlerFunc {
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
		response, ok := storeDB.Read(storeID)
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
		// Retrieve POST payload
		request := &Item{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Sanitize
		request.StoreUUID = storeID
		request.TimeCreated = TimeNowIsoString()
		if request.VATPercent >= 1 {
			// VAT provided as full % number instead of fraction as >=1 would mean >=100%
			// e.g.: 19 provided => 19 / 100 = 0.19
			request.VATPercent = request.VATPercent / 100
		}
		if request.Categories == nil {
			request.Categories = make([]string, 0)
		}
		if request.Colors == nil {
			request.Colors = make([]Category, 0)
		}
		if request.ThumbnailURLs == nil {
			request.ThumbnailURLs = make([]ItemImage, 0)
		} else {
			newArray := make([]ItemImage, 0)
			var uUID string
			// Convert Base64 to URL
			for _, img := range request.ThumbnailURLs {
				if img.URL == "" {
					continue
				}
				uUID, err = saveThumbnailImage(filesDB, user, img.URL)
				if err != nil {
					continue
				}
				newArray = append(newArray, ItemImage{
					URL:     fmt.Sprintf("files/public/get/%s", uUID),
					Caption: img.Caption,
				})
			}
			if len(newArray) > 0 {
				request.ThumbnailURLs = newArray
			}
		}
		if request.ThumbnailAnimatedURLs == nil {
			request.ThumbnailAnimatedURLs = make([]ItemImage, 0)
		}
		if request.BannerURLs == nil {
			request.BannerURLs = make([]ItemImage, 0)
		}
		if request.BannerAnimatedURLs == nil {
			request.BannerAnimatedURLs = make([]ItemImage, 0)
		}
		if request.Variations == nil {
			request.Variations = make([]ItemVariation, 0)
		} else {
			// Check if there are duplicate variations
			vars := map[string]string{}
			var varVars map[string]string
			for _, variation := range request.Variations {
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
			var done bool
			for {
				done = true
				for ix, variation := range request.Variations {
					if variation.Name == "" {
						request.Variations = append(request.Variations[:ix], request.Variations[ix+1:]...)
						done = false
						break
					}
				}
				if done {
					break
				}
			}
		}
		if request.Attributes == nil {
			request.Attributes = make([]ItemAttribute, 0)
		} else {
			var done bool
			for {
				done = true
				for ix, att := range request.Attributes {
					if att.Name == "" {
						request.Attributes = append(request.Attributes[:ix], request.Attributes[ix+1:]...)
						done = false
						break
					}
				}
				if done {
					break
				}
			}
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(jsonEntry, map[string]string{
			"pid": request.StoreUUID,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleItemGet(analyticsDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// user := r.Context().Value("user").(*User)
		// if user == nil {
		//   http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		//   return
		// }
		itemID := chi.URLParam(r, "itemID")
		if itemID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve item
		response, ok := db.Read(itemID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		item := &Item{}
		err := json.Unmarshal(response.Data, item)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Is there an analytics entry?
		analytics := &Analytics{}
		if item.AnalyticsUUID != "" {
			anaBytes, txn := analyticsDB.Get(item.AnalyticsUUID)
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
							_ = analyticsDB.Update(txn, item.AnalyticsUUID, jsonAna, map[string]string{})
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
				// Insert analytics while returning its UUID to the item for reference
				itemBytes, txnItem := db.Get(itemID)
				defer txnItem.Discard()
				item.AnalyticsUUID, err = analyticsDB.Insert(jsonAna, map[string]string{})
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				// Update item
				itemJson, err := json.Marshal(item)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(txnItem, itemBytes.uUID, itemJson, map[string]string{
					"pid": item.StoreUUID,
				})
			}
		}
		render.JSON(w, r, &ItemEntry{
			Item: item,
			UUID: itemID,
		})
	}
}

func (db *GoDB) handleItemQuery(storeDB, analyticsDB *GoDB,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		timeStart := time.Now()
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &ItemQuery{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve all Item entries
		resp, err := db.Select(map[string]string{
			"pid": storeID,
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		queryResponse := &ItemQueryResponse{
			TimeSeconds: 0,
			Items:       make([]*ItemContainer, 0),
		}
		response := <-resp
		if len(response) < 1 {
			render.JSON(w, r, queryResponse)
			return
		}
		// Turn query text into a full regex pattern
		words, p := GetRegexQuery(request.Query)
		var container *ItemContainer
		var item *Item
		var analytics *Analytics
		var points int64
		var accuracy float64
		b := false
		for _, entry := range response {
			item = &Item{}
			err = json.Unmarshal(entry.Data, item)
			if err != nil {
				continue
			}
			// Flip boolean on each iteration
			b = !b
			accuracy, points = GetItemQueryPoints(item, request, p, words, b)
			if points <= 0.0 {
				continue
			}
			// Truncate item description
			if item.Description != "" {
				item.Description = EllipticalTruncate(item.Description, 200)
			}
			// Load analytics if available
			analytics = &Analytics{}
			if item.AnalyticsUUID != "" {
				anaBytes, okAna := analyticsDB.Read(item.AnalyticsUUID)
				if okAna {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						analytics = &Analytics{}
					}
				}
			}
			container = &ItemContainer{
				UUID:      entry.uUID,
				Item:      item,
				Analytics: analytics,
				Accuracy:  accuracy,
			}
			queryResponse.Items = append(queryResponse.Items, container)
		}
		// Sort entries by accuracy
		if len(queryResponse.Items) > 1 {
			sort.SliceStable(
				queryResponse.Items, func(i, j int) bool {
					return queryResponse.Items[i].Accuracy > queryResponse.Items[j].Accuracy
				},
			)
		}
		duration := time.Since(timeStart)
		queryResponse.TimeSeconds = duration.Seconds()
		render.JSON(w, r, queryResponse)
	}
}

func GetItemQueryPoints(
	item *Item, query *ItemQuery, p *regexp.Regexp, words map[string]*QueryWord, b bool,
) (float64, int64) {
	// Get all matches in selected fields
	var mAtts, mCats, mName, mDesc, mKeys []string
	if query.Fields == "" || strings.Contains(query.Fields, "title") {
		mName = p.FindAllString(item.Name, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "desc") {
		mDesc = p.FindAllString(item.Description, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "keys") {
		mKeys = p.FindAllString(item.Keywords, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "cats") {
		if len(item.Categories) > 0 {
			var cats string
			for _, cat := range item.Categories {
				cats += fmt.Sprintf("%s ", cat)
			}
			mCats = p.FindAllString(cats, -1)
		}
	}
	if query.Fields == "" || strings.Contains(query.Fields, "attr") {
		if len(item.Attributes) > 0 {
			var attr string
			for _, att := range item.Attributes {
				attr += fmt.Sprintf("%s %s %s %f", att.Name, att.Description, att.StringValue, att.NumberValue)
			}
			mAtts = p.FindAllString(attr, -1)
		}
	}
	if len(mAtts) < 1 && len(mCats) < 1 && len(mName) < 1 && len(mDesc) < 1 && len(mKeys) < 1 {
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
	for _, word := range mCats {
		if words[strings.ToLower(word)] != nil {
			words[strings.ToLower(word)].B = b
		} else {
			words[strings.ToLower(word)] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
	for _, word := range mAtts {
		if words[strings.ToLower(word)] != nil {
			words[strings.ToLower(word)].B = b
		} else {
			words[strings.ToLower(word)] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
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
	for _, word := range mKeys {
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

func (db *GoDB) handleItemDelete(storeDB, analyticsDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		itemID := chi.URLParam(r, "itemID")
		if itemID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve item
		response, ok := db.Read(itemID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		item := &Item{}
		err := json.Unmarshal(response.Data, item)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Retrieve store
		storeResp, ok := storeDB.Read(item.StoreUUID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		store := &Store{}
		err = json.Unmarshal(storeResp.Data, store)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != store.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Is there an analytics entry?
		if item.AnalyticsUUID != "" {
			_ = analyticsDB.Delete(item.AnalyticsUUID, []string{})
		}
		// Delete item
		_ = db.Delete(itemID, []string{"pid"})
	}
}

func (db *GoDB) handleItemModification(storeDB, filesDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		itemID := chi.URLParam(r, "itemID")
		if itemID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve item
		var err error
		response, ok := db.Read(itemID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		item := &Item{}
		err = json.Unmarshal(response.Data, item)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Retrieve POST payload
		request := &ItemModification{}
		if err = render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Is user owner?
		response, ok = storeDB.Read(item.StoreUUID)
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
				err = db.changeItemImage(filesDB, user, itemID, request, false, false)
			} else if request.Field == "burl" {
				err = db.changeItemImage(filesDB, user, itemID, request, true, false)
			}
		} else if request.Type == "del" {
			if request.Field == "iurl" {
				err = db.removeItemImage(filesDB, user, itemID, request, false, false)
			} else if request.Field == "burl" {
				err = db.removeItemImage(filesDB, user, itemID, request, true, false)
			}
		}
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
}

func saveThumbnailImage(filesDB *GoDB, user *User, base64 string) (string, error) {
	if base64 == "" {
		return "", nil
	}
	// Check file size
	fileSize := GetBase64BinaryLength(base64)
	if fileSize > 20*MiB {
		return "", nil
	}
	// Save image
	fileRequest := &FileSubmission{
		DataBase64: base64,
		Filename:   "thumbnail-item",
		IsPrivate:  false,
	}
	fileSizeMB := float64(fileSize) / float64(1*MiB)
	uUID, err := filesDB.SaveBase64AsFile(user, fileRequest, fileSizeMB)
	if err != nil {
		return "", err
	}
	return uUID, nil
}

func (db *GoDB) changeItemImage(
	filesDB *GoDB, user *User, itemID string, request *ItemModification, isBanner, isAnimated bool,
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
		filename = "banner-item"
	} else {
		filename = "thumbnail-item"
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
	// Retrieve item
	response, txn := db.Get(itemID)
	if txn == nil {
		return nil
	}
	defer txn.Discard()
	item := &Item{}
	err = json.Unmarshal(response.Data, item)
	if err != nil {
		return err
	}
	// Set image url
	if isBanner {
		item.BannerURLs = append(item.BannerURLs, ItemImage{
			URL:     fmt.Sprintf("files/public/get/%s", uUID),
			Caption: request.MetaValue,
		})
	} else {
		item.ThumbnailURLs = append(item.ThumbnailURLs, ItemImage{
			URL:     fmt.Sprintf("files/public/get/%s", uUID),
			Caption: request.MetaValue,
		})
	}
	jsonEntry, err := json.Marshal(item)
	if err != nil {
		return err
	}
	err = db.Update(txn, response.uUID, jsonEntry, map[string]string{
		"pid": FIndex(item.StoreUUID),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) removeItemImage(
	filesDB *GoDB, user *User, itemID string, request *ItemModification, isBanner, isAnimated bool,
) error {
	if request.NewValue == "" {
		return nil
	}
	ix, err := strconv.ParseInt(request.NewValue, 10, 64)
	// Retrieve item
	response, txn := db.Get(itemID)
	if txn == nil {
		return nil
	}
	defer txn.Discard()
	item := &Item{}
	err = json.Unmarshal(response.Data, item)
	if err != nil {
		return err
	}
	// remove image url
	if isBanner {
		item.BannerURLs = append(item.BannerURLs[:ix], item.BannerURLs[ix+1:]...)
	} else {
		item.ThumbnailURLs = append(item.ThumbnailURLs[:ix], item.ThumbnailURLs[ix+1:]...)
	}
	jsonEntry, err := json.Marshal(item)
	if err != nil {
		return err
	}
	err = db.Update(txn, response.uUID, jsonEntry, map[string]string{
		"pid": FIndex(item.StoreUUID),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) handleItemEdit(storeDB, filesDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		itemID := chi.URLParam(r, "itemID")
		if itemID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve item
		response, ok := db.Read(itemID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		item := &Item{}
		err := json.Unmarshal(response.Data, item)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		storeID := item.StoreUUID
		response, ok = storeDB.Read(storeID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		store := &Store{}
		err = json.Unmarshal(response.Data, store)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &Item{}
		if err = render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.VATPercent >= 1 {
			// VAT provided as full % number instead of fraction as >=1 would mean >=100%
			// e.g.: 19 provided => 19 / 100 = 0.19
			request.VATPercent = request.VATPercent / 100
		}
		if request.Categories == nil {
			request.Categories = make([]string, 0)
		}
		if request.Colors == nil {
			request.Colors = make([]Category, 0)
		}
		if request.ThumbnailURLs == nil {
			request.ThumbnailURLs = make([]ItemImage, 0)
		} else {
			newArray := make([]ItemImage, 0)
			var uUID string
			// Convert Base64 to URL
			for _, img := range request.ThumbnailURLs {
				if img.URL == "" {
					continue
				}
				if len(img.URL) >= 5 && img.URL[0:5] == "files" {
					newArray = append(newArray, img)
					continue
				}
				uUID, err = saveThumbnailImage(filesDB, user, img.URL)
				if err != nil {
					continue
				}
				newArray = append(newArray, ItemImage{
					URL:     fmt.Sprintf("files/public/get/%s", uUID),
					Caption: img.Caption,
				})
			}
			if len(newArray) > 0 {
				request.ThumbnailURLs = newArray
			}
		}
		if request.ThumbnailAnimatedURLs == nil {
			request.ThumbnailAnimatedURLs = make([]ItemImage, 0)
		}
		if request.BannerURLs == nil {
			request.BannerURLs = make([]ItemImage, 0)
		}
		if request.BannerAnimatedURLs == nil {
			request.BannerAnimatedURLs = make([]ItemImage, 0)
		}
		if request.Variations == nil {
			request.Variations = make([]ItemVariation, 0)
		} else {
			// Check if there are duplicate variations
			vars := map[string]string{}
			var varVars map[string]string
			for _, variation := range request.Variations {
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
			var done bool
			for {
				done = true
				for ix, variation := range request.Variations {
					if variation.Name == "" {
						request.Variations = append(request.Variations[:ix], request.Variations[ix+1:]...)
						done = false
						break
					}
				}
				if done {
					break
				}
			}
		}
		if request.Attributes == nil {
			request.Attributes = make([]ItemAttribute, 0)
		} else {
			var done bool
			for {
				done = true
				for ix, att := range request.Attributes {
					if att.Name == "" {
						request.Attributes = append(request.Attributes[:ix], request.Attributes[ix+1:]...)
						done = false
						break
					}
				}
				if done {
					break
				}
			}
		}
		// Update
		_, txn := db.Get(itemID)
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(txn, itemID, jsonEntry, map[string]string{
			"pid": FIndex(request.StoreUUID),
		})
	}
}
