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

const ItemDB = "m12"

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
	Brand                 string          `json:"brand"`
	Manufacturer          string          `json:"manu"`
	DateOfAppearance      string          `json:"doa"`
}

type BulkItem struct {
	Items []Item `json:"items"`
}

type BulkItemEdit struct {
	Items []ItemEdit `json:"items"`
}

type ItemEdit struct {
	UUID    string `json:"uid"`
	Payload Item   `json:"payload"`
}

type BulkItemResults struct {
	Results []string `json:"results"`
}

type BulkItemEditResults struct {
	Results []bool `json:"results"`
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
	GroupingKey string               `json:"key"`
	NumberValue float64              `json:"nval"`
	Optional    bool                 `json:"opt"`
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
	Query      string           `json:"query"`
	Type       string           `json:"type"`
	Fields     string           `json:"fields"`
	State      string           `json:"state"`
	MinCost    float64          `json:"minCost"`
	MaxCost    float64          `json:"maxCost"`
	Variations []VariationQuery `json:"vars"`
	Categories []string         `json:"cats"`
	Colors     []string         `json:"clrs"`
	Brand      string           `json:"brand"`
}

type VariationQuery struct {
	Name         string   `json:"t"`
	StringValues []string `json:"svals"`
	Csv          string
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

type BulkItemModification struct {
	Modifications []ItemModification `json:"mods"`
}

type ItemFilters struct {
	Variations []ItemVariation `json:"vars"`
	Colors     []Category      `json:"clrs"`
	Categories []string        `json:"cats"`
	Brands     []string        `json:"brands"`
	MinCost    float64         `json:"min"`
	MaxCost    float64         `json:"max"`
	AvgCost    float64         `json:"avg"`
}

func (db *GoDB) PublicItemsEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth, mainDB *GoDB) {
	r.Route("/items/public", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/query/{storeID}", db.handleItemQuery())
		// ###########
		// ### GET ###
		// ###########
		r.Get("/get/{itemID}", db.handleItemGet())
		r.Get("/filters/{storeID}", db.handleItemGetFilters())
	})
}

func (db *GoDB) ProtectedItemEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth, mainDB *GoDB,
) {
	r.Route("/items/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/create/{storeID}", db.handleItemCreate(mainDB))
		r.Post("/edit/{itemID}", db.handleItemEdit(mainDB))
		r.Post("/mod/{itemID}", db.handleItemModification(mainDB))
		// Bulk operations
		r.Route("/bulk", func(r chi.Router) {
			r.Post("/create/{storeID}", db.handleBulkItemCreate(mainDB))
			r.Post("/edit/{storeID}", db.handleItemEdit(mainDB))
		})
		// ###########
		// ### GET ###
		// ###########
		r.Get("/delete/{itemID}", db.handleItemDelete(mainDB))
	})
}

func (a *Item) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing t")
	}
	if a.Description == "" {
		return errors.New("missing desc")
	}
	return nil
}

func (a *BulkItem) Bind(_ *http.Request) error {
	if len(a.Items) < 1 {
		return errors.New("missing items")
	}
	return nil
}

func (a *BulkItemEdit) Bind(_ *http.Request) error {
	if len(a.Items) < 1 {
		return errors.New("missing items")
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

func (a *BulkItemModification) Bind(_ *http.Request) error {
	if len(a.Modifications) < 1 {
		return errors.New("missing mods")
	}
	return nil
}

func (db *GoDB) handleItemCreate(mainDB *GoDB) http.HandlerFunc {
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
		response, ok := mainDB.Read(StoreDB, storeID)
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
		uUID := db.doCreateItem(w, user, request, storeID, false)
		if uUID == "" {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleBulkItemCreate(mainDB *GoDB) http.HandlerFunc {
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
		response, ok := mainDB.Read(StoreDB, storeID)
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
		request := &BulkItem{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bulkResults := BulkItemResults{Results: make([]string, len(request.Items))}
		for i, item := range request.Items {
			bulkResults.Results[i] = db.doCreateItem(w, user, &item, storeID, true)
		}
		render.JSON(w, r, bulkResults)
	}
}

func (db *GoDB) doCreateItem(w http.ResponseWriter, user *User, request *Item, storeID string, noErrors bool) string {
	var err error
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
			uUID, err = saveThumbnailImage(db, user, img.URL)
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
				if !noErrors {
					http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				}
				return ""
			}
			vars[variation.Name] = "x"
			// Check if there are duplicate variation variations
			varVars = map[string]string{}
			for _, varVar := range variation.Variations {
				if varVars[varVar.StringValue] != "" {
					if !noErrors {
						http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
					}
					return ""
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
		if !noErrors {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return ""
	}
	index := map[string]string{
		"pid": FIndex(request.StoreUUID),
	}
	index = createItemIndex(request, index, false)
	uUID, err := db.Insert(ItemDB, jsonEntry, index)
	if err != nil {
		if !noErrors {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return ""
	}
	return uUID
}

func (db *GoDB) handleItemGet() http.HandlerFunc {
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
		response, ok := db.Read(ItemDB, itemID)
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
			anaBytes, txn := db.Get(AnaDB, item.AnalyticsUUID)
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
							_ = db.Update(AnaDB, txn, item.AnalyticsUUID, jsonAna, map[string]string{})
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
				itemBytes, txnItem := db.Get(ItemDB, itemID)
				defer txnItem.Discard()
				item.AnalyticsUUID, err = db.Insert(AnaDB, jsonAna, map[string]string{})
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
				err = db.Update(ItemDB, txnItem, itemBytes.uUID, itemJson, map[string]string{
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

func (db *GoDB) handleItemQuery() http.HandlerFunc {
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
		// Options?
		options := r.Context().Value("pagination").(*SelectOptions)
		if options.MaxResults <= 0 {
			options.MaxResults = 25
		}
		maxResults := int(options.MaxResults)
		// Retrieve all Item entries respecting the query index filters
		var customIndices = false
		index := map[string]string{}
		if request.Brand != "" {
			index["pid-brand"] =
				fmt.Sprintf("%s;%s", storeID, strings.ToLower(request.Brand))
			customIndices = true
		}
		if len(request.Categories) > 0 {
			for i, category := range request.Categories {
				index[fmt.Sprintf("pid-cat[%d", i)] =
					fmt.Sprintf("%s;%s", storeID, strings.ToLower(category))
			}
			customIndices = true
		}
		if len(request.Colors) > 0 {
			for i, color := range request.Colors {
				index[fmt.Sprintf("pid-clrs[%d", i)] =
					fmt.Sprintf("%s;%s", storeID, strings.ToLower(color))
			}
			customIndices = true
		}
		// Search for all items if no index filters were supplied
		if !customIndices {
			index["pid"] = storeID
		}
		resp, err := db.Select(ItemDB, index, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		queryResponse := &ItemQueryResponse{
			TimeSeconds: 0,
			Items:       make([]*ItemContainer, 0),
		}
		// Turn query text into a full regex pattern
		words, p := GetRegexQuery(request.Query)
		// Build csv (comma seperated values) content for variations query if provided
		if len(request.Variations) > 0 {
			for ix, variation := range request.Variations {
				if len(variation.StringValues) > 0 {
					for i := 0; i < len(variation.StringValues); i++ {
						request.Variations[ix].Csv += fmt.Sprintf("|%s|", request.Variations[ix].StringValues[i])
					}
				}
			}
		}
		// Set up variables
		var container *ItemContainer
		var item *Item
		var analytics *Analytics
		var points int64
		var accuracy float64
		b := false
		// Await response as late as possible
		response := <-resp
		if len(response) < 1 {
			render.JSON(w, r, queryResponse)
			return
		}
		// Iterate over all items found
		for _, entry := range response {
			item = &Item{}
			err = json.Unmarshal(entry.Data, item)
			if err != nil {
				continue
			}
			// Compare cost if provided
			if request.MinCost != 0.0 && item.NetPrice*(1+item.VATPercent) < request.MinCost {
				continue
			}
			if request.MaxCost != 0.0 && item.NetPrice*(1+item.VATPercent) > request.MaxCost {
				continue
			}
			// Compare variations if provided
			if len(request.Variations) > 0 {
				points = GetItemVariationPoints(item, request)
				if points <= 0 {
					continue
				}
			}
			// Flip boolean on each iteration
			b = !b
			accuracy, points = GetItemQueryPoints(item, request, p, words, b)
			if points <= 0 {
				continue
			}
			// Truncate item description
			if item.Description != "" {
				item.Description = EllipticalTruncate(item.Description, 200)
			}
			// Load analytics if available
			analytics = &Analytics{}
			if item.AnalyticsUUID != "" {
				anaBytes, okAna := db.Read(AnaDB, item.AnalyticsUUID)
				if okAna {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						analytics = &Analytics{}
					}
				}
			}
			// Add result
			container = &ItemContainer{
				UUID:      entry.uUID,
				Item:      item,
				Analytics: analytics,
				Accuracy:  accuracy,
			}
			queryResponse.Items = append(queryResponse.Items, container)
			// Stop if we have reached the maximum amount of results
			if len(queryResponse.Items) >= maxResults {
				break
			}
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
	var mAtts, mCats, mName, mDesc, mKeys, mClrs []string
	// *** Title ***
	if query.Fields == "" || strings.Contains(query.Fields, "title") {
		mName = p.FindAllString(item.Name, -1)
	}
	// *** Description ***
	if query.Fields == "" || strings.Contains(query.Fields, "desc") {
		mDesc = p.FindAllString(item.Description, -1)
	}
	// *** Keywords ***
	if query.Fields == "" || strings.Contains(query.Fields, "keys") {
		mKeys = p.FindAllString(item.Keywords, -1)
	}
	// *** Categories ***
	if query.Fields == "" || strings.Contains(query.Fields, "cats") {
		if len(item.Categories) > 0 {
			var cats string
			for _, cat := range item.Categories {
				cats += fmt.Sprintf("%s ", cat)
			}
			mCats = p.FindAllString(cats, -1)
		}
	}
	// *** Attributes ***
	if query.Fields == "" || strings.Contains(query.Fields, "attr") {
		if len(item.Attributes) > 0 {
			var attr string
			for _, att := range item.Attributes {
				attr += fmt.Sprintf("%s %s %s %f", att.Name, att.Description, att.StringValue, att.NumberValue)
			}
			mAtts = p.FindAllString(attr, -1)
		}
	}
	// *** Colors ***
	if query.Fields == "" || strings.Contains(query.Fields, "clrs") {
		if len(item.Colors) > 0 {
			var clrs string
			for _, color := range item.Colors {
				clrs += fmt.Sprintf("%s %s", color.Name, color.ColorHex)
			}
			mClrs = p.FindAllString(clrs, -1)
		}
	}
	if len(mName) < 1 && len(mDesc) < 1 && len(mKeys) < 1 && len(mAtts) < 1 && len(mCats) < 1 && len(mClrs) < 1 {
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
	for _, word := range mClrs {
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

func GetItemVariationPoints(
	item *Item, query *ItemQuery,
) int64 {
	// Check if item has main variation
	var found bool
	for _, variation := range query.Variations {
		found = false
		for _, itemVariation := range item.Variations {
			if itemVariation.Name == variation.Name {
				// Main variation exists, check if sub variation exists
				if len(itemVariation.Variations) < 1 {
					// If item variation has no sub variation exit since we will be comparing sub variations
					return 0
				}
				for _, itemSubVariation := range itemVariation.Variations {
					if strings.Contains(variation.Csv, fmt.Sprintf("|%s|", itemSubVariation.StringValue)) {
						// Return upon finding the first sub variation match to avoid unnecessary computing
						found = true
						break
					}
				}
				if found {
					break
				}
				// Exit if we have not found a sub variation
				return 0
			}
		}
		if found {
			continue
		}
		// Exit if we have not found the first variation
		return 0
	}
	if found {
		return 1
	}
	// Exit if we have not found a variation
	return 0
}

func (db *GoDB) handleItemDelete(mainDB *GoDB) http.HandlerFunc {
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
		response, ok := db.Read(ItemDB, itemID)
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
		storeResp, ok := mainDB.Read(StoreDB, item.StoreUUID)
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
			_ = db.Delete(AnaDB, item.AnalyticsUUID, []string{})
		}
		// Delete item
		_ = db.Delete(ItemDB, itemID, []string{"pid"})
	}
}

func (db *GoDB) handleItemModification(mainDB *GoDB) http.HandlerFunc {
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
		response, ok := db.Read(ItemDB, itemID)
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
		response, ok = mainDB.Read(StoreDB, item.StoreUUID)
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
				err = db.changeItemImage(user, itemID, request, false, false)
			} else if request.Field == "burl" {
				err = db.changeItemImage(user, itemID, request, true, false)
			}
		} else if request.Type == "del" {
			if request.Field == "iurl" {
				err = db.removeItemImage(user, itemID, request, false, false)
			} else if request.Field == "burl" {
				err = db.removeItemImage(user, itemID, request, true, false)
			}
		}
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	}
}

func saveThumbnailImage(rapidDB *GoDB, user *User, base64 string) (string, error) {
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
	uUID, err := rapidDB.SaveBase64AsFile(user, fileRequest, fileSizeMB)
	if err != nil {
		return "", err
	}
	return uUID, nil
}

func (db *GoDB) changeItemImage(
	user *User, itemID string, request *ItemModification, isBanner, isAnimated bool,
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
	uUID, err := db.SaveBase64AsFile(user, fileRequest, fileSizeMB)
	if err != nil {
		return err
	}
	// Retrieve item
	response, txn := db.Get(ItemDB, itemID)
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
	err = db.Update(ItemDB, txn, response.uUID, jsonEntry, map[string]string{
		"pid": FIndex(item.StoreUUID),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) removeItemImage(
	user *User, itemID string, request *ItemModification, isBanner, isAnimated bool,
) error {
	if request.NewValue == "" {
		return nil
	}
	ix, err := strconv.ParseInt(request.NewValue, 10, 64)
	// Retrieve item
	response, txn := db.Get(ItemDB, itemID)
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
	err = db.Update(ItemDB, txn, response.uUID, jsonEntry, map[string]string{
		"pid": FIndex(item.StoreUUID),
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) handleItemEdit(mainDB *GoDB) http.HandlerFunc {
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
		response, ok := db.Read(ItemDB, itemID)
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
		response, ok = mainDB.Read(StoreDB, storeID)
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
		db.doEditItem(w, user, request, itemID, true)
	}
}

func (db *GoDB) handleBulkItemEdit(mainDB *GoDB) http.HandlerFunc {
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
		responseStore, ok := mainDB.Read(StoreDB, storeID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		store := &Store{}
		err := json.Unmarshal(responseStore.Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Retrieve POST payload
		request := &BulkItemEdit{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		bulkEditResults := BulkItemEditResults{Results: make([]bool, len(request.Items))}
		for i, entry := range request.Items {
			// Retrieve item
			response, ok := db.Read(ItemDB, entry.UUID)
			if !ok {
				bulkEditResults.Results[i] = false
				continue
			}
			item := &Item{}
			err = json.Unmarshal(response.Data, item)
			if err != nil {
				bulkEditResults.Results[i] = false
				continue
			}
			bulkEditResults.Results[i] = db.doEditItem(w, user, &entry.Payload, entry.UUID, false)
		}
		render.JSON(w, r, bulkEditResults)
	}
}

func (db *GoDB) doEditItem(w http.ResponseWriter, user *User, request *Item, itemID string, noErrors bool) bool {
	var err error
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
			uUID, err = saveThumbnailImage(db, user, img.URL)
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
				if !noErrors {
					http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				}
				return false
			}
			vars[variation.Name] = "x"
			// Check if there are duplicate variation variations
			varVars = map[string]string{}
			for _, varVar := range variation.Variations {
				if varVars[varVar.StringValue] != "" {
					if !noErrors {
						http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
					}
					return false
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
	_, txn := db.Get(ItemDB, itemID)
	jsonEntry, err := json.Marshal(request)
	if err != nil {
		if !noErrors {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		return false
	}
	index := map[string]string{
		"pid": FIndex(request.StoreUUID),
	}
	index = createItemIndex(request, index, true)
	err = db.Update(ItemDB, txn, itemID, jsonEntry, index)
	if err != nil {
		return false
	}
	return true
}

func (db *GoDB) handleItemGetFilters() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		storeID := chi.URLParam(r, "storeID")
		if storeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve all Item entries
		resp, err := db.Select(ItemDB, map[string]string{
			"pid": storeID,
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		queryResponse := &ItemFilters{
			Variations: make([]ItemVariation, 0),
			Colors:     make([]Category, 0),
			Categories: make([]string, 0),
			Brands:     make([]string, 0),
			MinCost:    0,
			MaxCost:    0,
			AvgCost:    0,
		}
		response := <-resp
		if len(response) < 1 {
			render.JSON(w, r, queryResponse)
			return
		}
		var item *Item
		var gross float64
		var count int
		var groupKey string
		cacheMap := map[string]bool{}
		var groupKeyExists bool
		var ix int
		for _, entry := range response {
			item = &Item{}
			err = json.Unmarshal(entry.Data, item)
			if err != nil {
				continue
			}
			// Cost
			if item.NetPrice > 0 {
				count += 1
				gross = item.NetPrice * (1 + item.VATPercent)
				// We will divide the average cost by the amount later on to get the actual average
				queryResponse.AvgCost += gross
				// Min/Max?
				if queryResponse.MinCost == 0 || gross < queryResponse.MinCost {
					queryResponse.MinCost = gross
				}
				if queryResponse.MaxCost == 0 || gross > queryResponse.MaxCost {
					queryResponse.MaxCost = gross
				}
			}
			// Variations
			if len(item.Variations) > 0 {
				for _, variation := range item.Variations {
					// Check if main variation exists yet
					groupKey = fmt.Sprintf("vari-%s", variation.Name)
					groupKeyExists = cacheMap[groupKey]
					if !groupKeyExists {
						// Doesn't exist -> Add
						cacheMap[groupKey] = true
						queryResponse.Variations = append(queryResponse.Variations, variation)
						for _, subVariation := range variation.Variations {
							groupKey = fmt.Sprintf("vari-%s;%s", variation.Name, subVariation.StringValue)
							cacheMap[groupKey] = true
						}
					} else {
						// Exists -> Check for missing sub variations
						for i, tVariation := range queryResponse.Variations {
							if tVariation.Name == variation.Name {
								ix = i
								break
							}
						}
						for _, subVariation := range variation.Variations {
							groupKey = fmt.Sprintf("vari-%s;%s", variation.Name, subVariation.StringValue)
							groupKeyExists = cacheMap[groupKey]
							if !groupKeyExists {
								// Doesn't exist -> Add
								cacheMap[groupKey] = true
								queryResponse.Variations[ix].Variations = append(
									queryResponse.Variations[ix].Variations, subVariation)
							}
						}
					}
				}
			}
			// Categories
			if len(item.Categories) > 0 {
				for _, category := range item.Categories {
					groupKey = fmt.Sprintf("cat-%s", category)
					groupKeyExists = cacheMap[groupKey]
					if !groupKeyExists {
						cacheMap[groupKey] = true
						queryResponse.Categories = append(queryResponse.Categories, category)
					}
				}
			}
			// Colors
			if len(item.Colors) > 0 {
				for _, color := range item.Colors {
					groupKey = fmt.Sprintf("clrs-%s", color.Name)
					groupKeyExists = cacheMap[groupKey]
					if !groupKeyExists {
						cacheMap[groupKey] = true
						queryResponse.Colors = append(queryResponse.Colors, color)
					}
				}
			}
			// Brands
			if item.Brand != "" {
				groupKey = fmt.Sprintf("brand-%s", item.Brand)
				groupKeyExists = cacheMap[groupKey]
				if !groupKeyExists {
					cacheMap[groupKey] = true
					queryResponse.Brands = append(queryResponse.Brands, item.Brand)
				}
			}
		}
		// Actually calculate average cost
		if count > 0 && queryResponse.AvgCost != 0 {
			queryResponse.AvgCost = queryResponse.AvgCost / float64(count)
		}
		// Sort main variations
		if len(queryResponse.Variations) > 0 {
			sort.SliceStable(
				queryResponse.Variations, func(i, j int) bool {
					return queryResponse.Variations[i].Name < queryResponse.Variations[j].Name
				},
			)
			// Sort sub variations
			for ix := range queryResponse.Variations {
				if len(queryResponse.Variations[ix].Variations) > 0 {
					sort.SliceStable(
						queryResponse.Variations[ix].Variations, func(i, j int) bool {
							return queryResponse.Variations[ix].Variations[i].StringValue <
								queryResponse.Variations[ix].Variations[j].StringValue
						},
					)
				}
			}
		}
		render.JSON(w, r, queryResponse)
	}
}

// createItemIndex() adds relevant data to the item's index, e.g. categories
func createItemIndex(item *Item, index map[string]string, isUpdate bool) map[string]string {
	// *** Categories ***
	if len(item.Categories) > 0 {
		for i, category := range item.Categories {
			// We append "[i" to the key as the index type is map
			// We omit "]" to save time on more truncating/splitting than necessary
			index[fmt.Sprintf("pid-cat[%d", i)] =
				fmt.Sprintf("%s;%s", item.StoreUUID, strings.ToLower(category))
		}
	} else {
		if isUpdate {
			// When updating we need to clear previous entries
			// ... in case the new item does not have those values
			index["pid-cat"] = ""
		}
	}
	// *** Brand ***
	if item.Brand != "" {
		index["pid-brand"] =
			fmt.Sprintf("%s;%s", item.StoreUUID, strings.ToLower(item.Brand))
	} else {
		if isUpdate {
			index["pid-brand"] = ""
		}
	}
	// *** Manufacturer ***
	if item.Manufacturer != "" {
		index["pid-manu"] =
			fmt.Sprintf("%s;%s", item.StoreUUID, strings.ToLower(item.Manufacturer))
	} else {
		if isUpdate {
			index["pid-manu"] = ""
		}
	}
	// *** Colors ***
	if len(item.Colors) > 0 {
		for i, color := range item.Colors {
			// We append "[i" to the key as the index type is map
			// We omit "]" to save time on more truncating/splitting than necessary
			index[fmt.Sprintf("pid-clrs[%d", i)] =
				fmt.Sprintf("%s;%s", item.StoreUUID, strings.ToLower(color.Name))
		}
	} else {
		if isUpdate {
			// When updating we need to clear previous entries
			// ... in case the new item does not have those values
			index["pid-clrs"] = ""
		}
	}
	return index
}
