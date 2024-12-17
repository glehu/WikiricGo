package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
	"regexp"
	"slices"
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

type ItemStock struct {
	UUID        string  `json:"uid"`
	TimeCreated int64   `json:"ts"`
	Amount      float64 `json:"amt"`
	Storage     string  `json:"stu"`
	Type        string  `json:"type"`
}

type BulkItemStockModificationRequest struct {
	Type          string                  `json:"type"` // ADD or SET
	Modifications []ItemStockModification `json:"mods"`
}

type ItemStockModification struct {
	UUID    string  `json:"uid"`
	Amount  float64 `json:"amt"`
	Storage string  `json:"stu"`
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
	UUID  string  `json:"uid"`
	Stock float64 `json:"stock"`
	*Item
}

type ItemContainer struct {
	UUID  string  `json:"uid"`
	Stock float64 `json:"stock"`
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
	MinStock   float64          `json:"minStock"`
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
	Amount     int             `json:"amt"`
	LastUpdate int64           `json:"lastUpdate"`
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

func (db *GoDB) ProtectedItemEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth, mainDB *GoDB, connector *Connector,
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
			r.Post("/edit/{storeID}", db.handleBulkItemEdit(mainDB))
			r.Post("/stock/{storeID}", db.handleBulkItemStockModification(mainDB))
		})
		// ###########
		// ### GET ###
		// ###########
		r.Get("/delete/{itemID}", db.handleItemDelete(mainDB))
		r.Get("/index/{storeID}", db.handleGenerateIndex(mainDB, connector))
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

func (a *BulkItemStockModificationRequest) Bind(_ *http.Request) error {
	if len(a.Modifications) < 1 {
		return errors.New("missing mods")
	}
	t := strings.ToLower(a.Type)
	if t != "add" && t != "set" {
		return errors.New("type not one of add or set")
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
		uUID := db.doCreateItem(w, user, request, storeID, false)
		if uUID == "" {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		}
		_, _ = fmt.Fprintln(w, uUID)
		go db.createStoreFilterCache(storeID)
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
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
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
					http.Error(w, "duplicate variations", http.StatusBadRequest)
				}
				return ""
			}
			vars[variation.Name] = "x"
			// Check if there are duplicate variation variations
			varVars = map[string]string{}
			for _, varVar := range variation.Variations {
				if varVars[varVar.StringValue] != "" {
					if !noErrors {
						http.Error(w, "duplicate sub-variations", http.StatusBadRequest)
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
		stockC, cncl := db.calculateItemStock(item.StoreUUID, itemID, "[main]")
		defer cncl()
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
		// Await stock response
		stk := <-stockC
		// Return item data to caller
		render.JSON(w, r, &ItemEntry{
			Item:  item,
			Stock: stk,
			UUID:  itemID,
		})
	}
}

func (db *GoDB) handleItemQuery() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		massQuery := r.URL.Query().Get("mass")
		if massQuery == "true" || massQuery == "1" {
			// TODO: Still in experimental mode! Does not work for the frontend!
			db.doItemMassQuery(w, r)
			return
		}
		wordQuery := r.URL.Query().Get("wrd")
		if wordQuery == "true" || wordQuery == "1" {
			db.doItemWordQuery(w, r)
			return
		}
		// Don't imprison the caller
		// ... we still need to handle an internal timeout, though,
		// ... as this literally only protects the caller
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		c := make(chan *ItemQueryResponse)
		// *** Start the request ***
		go db.doItemQuery(w, r, c, ctx)
		// Await response
		select {
		case <-ctx.Done():
			http.Error(w, http.StatusText(http.StatusGatewayTimeout), http.StatusGatewayTimeout)
		case resp := <-c:
			render.JSON(w, r, resp)
		}
	}
}

func (db *GoDB) doItemWordQuery(w http.ResponseWriter, r *http.Request) {
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
	if request.Brand != "" {
		request.Brand = strings.ToLower(request.Brand)
	}
	// Options?
	options := r.Context().Value("pagination").(*SelectOptions)
	if options.MaxResults <= 0 {
		options.MaxResults = 25
	}
	maxResults := int(options.MaxResults)
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
	var analytics *Analytics
	var points int64
	var accuracy float64
	var stockC chan float64
	var stk float64
	var cncl context.CancelFunc
	var err error
	var b bool
	hasStockFilter := request.MinStock > 0
	items := db.GetItemsFromWords(storeID, request.Query)
	queryResponse := &ItemQueryResponse{
		TimeSeconds: 0,
		Items:       make([]*ItemContainer, 0),
	}
	if len(items.Items) < 1 {
		duration := time.Since(timeStart)
		queryResponse.TimeSeconds = duration.Seconds()
		render.JSON(w, r, queryResponse)
		return
	}
	var item *Item
	for _, ic := range items.Items {
		item = ic.Item
		// Compare cost if provided
		if request.MinCost != 0.0 && item.NetPrice*(1+item.VATPercent) < request.MinCost {
			continue
		}
		if request.MaxCost != 0.0 && item.NetPrice*(1+item.VATPercent) > request.MaxCost {
			continue
		}
		if request.Brand != "" && strings.ToLower(item.Brand) != request.Brand {
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
		// Query content with provided prompt
		accuracy, points = GetItemQueryPoints(item, request, p, words, b)
		ic.Accuracy = accuracy
		// Final (optional) check
		if hasStockFilter {
			stockC, cncl = db.calculateItemStock(storeID, ic.UUID, "[main]")
			// Await answer
			stk = <-stockC
			if stk < request.MinStock {
				cncl()
				continue
			}
		} else {
			stk = 0.0
		}
		ic.Stock = stk
		// Truncate item description
		if item.Description != "" {
			item.Description = EllipticalTruncate(item.Description, 500)
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
				ic.Analytics = analytics
			}
		}
		queryResponse.Items = append(queryResponse.Items, ic)
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

func (db *GoDB) GetItemsFromWords(storeID, query string) *ItemQueryResponse {
	queryResponse := &ItemQueryResponse{
		TimeSeconds: 0,
		Items:       make([]*ItemContainer, 0),
	}
	if storeID == "" || query == "" {
		return queryResponse
	}
	// Construct index map with all words being queried
	index := map[string]string{}
	words := strings.Fields(query)
	for i, word := range words {
		word = strings.ToLower(strings.TrimSuffix(word, "*"))
		index[fmt.Sprintf("wrd-%s[%d", storeID, i)] = word
	}
	wordLen := len(words)
	// Retrieve slices of UUIDs mapped to words
	response, cancel, err := db.SSelect(
		ItemDB, index, nil, 4, 1, true, true,
	)
	defer cancel()
	if err != nil {
		return nil
	}
	// We cannot guarantee that both the title and description of an item will match
	// ...all words provided. We will basically just check if every word got matched at least once in total.
	var hits []bool
	var lst []string
	var item *Item
	var res *EntryResponse
	var ok bool
	var ixEntry []byte
	var cnts *MassEntryResponse
	var points int64
	var tmpLen int
	for entry := range response {
		if entry == nil {
			continue
		}
		lst = strings.Split(string(entry.Data), ";")
		if len(lst) == 0 {
			continue
		}
		// Get each item!
		for _, uid := range lst {
			res, ok = db.Read(ItemDB, uid)
			if !ok {
				continue
			}
			points = 0
			hits = make([]bool, wordLen)
			ixEntry = res.Data
			cnts = SearchInBytes(ixEntry, "t", words, 100)
			if cnts != nil && len(cnts.Counts) > 0 {
				for ix, wCount := range cnts.Counts {
					tmpLen = len(wCount)
					if tmpLen < 1 {
						continue
					}
					hits[ix] = true
					// Title means the most so we reward it!
					points += int64(tmpLen) * 2
				}
			}
			// We need to match the title
			if points <= 0 {
				continue
			}
			ixEntry = res.Data
			cnts = SearchInBytes(ixEntry, "desc", words, 100)
			if cnts != nil && len(cnts.Counts) > 0 {
				for ix, wCount := range cnts.Counts {
					tmpLen = len(wCount)
					if tmpLen < 1 {
						continue
					}
					hits[ix] = true
					points += int64(tmpLen)
				}
			}
			// Check if we matched every word at least once!
			for _, hit := range hits {
				if !hit {
					// TODO: Check importance of word missed e.g. was the input length less than x?
					points = 0
					break
				}
			}
			if points <= 0 {
				continue
			}
			item = &Item{}
			err = json.Unmarshal(res.Data, item)
			if err != nil {
				continue
			}
			queryResponse.Items = append(queryResponse.Items, &ItemContainer{
				UUID:      res.uUID,
				Stock:     0,
				Item:      item,
				Analytics: nil,
				Accuracy:  float64(points),
			})
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
	return queryResponse
}

func (db *GoDB) doItemMassQuery(w http.ResponseWriter, r *http.Request) {
	// Orchestrate a badger.Stream query over the database
	storeID := chi.URLParam(r, "storeID")
	if storeID == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	response := db.MassSearch(ItemDB, "pid", storeID,
		"desc", []string{"drift"},
		1000, 0, ctx)
	if response == nil {
		return
	}
	timer := time.NewTimer(4 * time.Second)
	var item *Item
	var err error
	for {
		select {
		case <-timer.C:
			fmt.Println("CANCELLED!")
			cancel()
			render.JSON(w, r, ItemQueryResponse{
				TimeSeconds: 0,
				Items:       nil,
			})
			return
		case <-ctx.Done():
			render.JSON(w, r, ItemQueryResponse{
				TimeSeconds: 0,
				Items:       nil,
			})
			return
		case entry := <-response:
			if entry == nil {
				continue
			}
			item = &Item{}
			err = json.Unmarshal(entry.Data, item)
			if err == nil {
				fmt.Println(len(entry.Counts[0]), "ENTRY:", item.Description)
			}
		}
	}
}

func (db *GoDB) doItemQuery(w http.ResponseWriter, r *http.Request, c chan *ItemQueryResponse, ctx context.Context) {
	timeStart := time.Now()
	queryResponse := &ItemQueryResponse{
		TimeSeconds: 0,
		Items:       make([]*ItemContainer, 0),
	}
	storeID := chi.URLParam(r, "storeID")
	if storeID == "" {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		c <- queryResponse
		return
	}
	// Retrieve POST payload
	request := &ItemQuery{}
	if err := render.Bind(r, request); err != nil {
		fmt.Println(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		c <- queryResponse
		return
	}
	// Options?
	options := r.Context().Value("pagination").(*SelectOptions)
	if options.MaxResults <= 0 {
		options.MaxResults = 25
	}
	// Fast search? We will not parse the items and only query specific fields
	fastT := r.URL.Query().Get("fast")
	isFast := false
	if fastT == "true" || fastT == "1" {
		isFast = true
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
			request.Categories[i] = strings.ToLower(category)
			index[fmt.Sprintf("pid-cat[%d", i)] =
				fmt.Sprintf("%s;%s;", storeID, request.Categories[i])
		}
		customIndices = true
	}
	if len(request.Colors) > 0 {
		for i, color := range request.Colors {
			index[fmt.Sprintf("pid-clrs[%d", i)] =
				fmt.Sprintf("%s;%s;", storeID, strings.ToLower(color))
		}
		customIndices = true
	}
	if request.Brand != "" {
		request.Brand = strings.ToLower(request.Brand)
	}
	// Search for all items if no index filters were supplied
	if !customIndices {
		index["pid"] = storeID
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
	hasStockFilter := request.MinStock > 0
	var container *ItemContainer
	var item *Item
	var analytics *Analytics
	var points int64
	var accuracy float64
	var stockC chan float64
	var stk float64
	var cncl context.CancelFunc
	var cnts *MassEntryResponse
	var wrds []string
	var ixEntry []byte
	if isFast {
		for wr := range words {
			wrds = append(wrds, wr)
		}
	}
	b := false
	// Iterate over all items found
	response, cancel, err := db.SSelect(ItemDB, index, nil, 4, int(options.MaxResults), true, false)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		c <- queryResponse
		return
	}
	for entry := range response {
		if isFast {
			// If user requested a fast search, we will not even parse the item at this point!
			// To still be able to allow for regex searching, we will still parse the item afterward,
			// ...so we use this superfast byte-level search to avoid looking at irrelevant entries. Smart!
			points = 0
			ixEntry = entry.Data
			cnts = SearchInBytes(ixEntry, "t", wrds, 100)
			if cnts != nil && len(cnts.Counts) > 0 {
				for _, wCount := range cnts.Counts {
					points += int64(len(wCount))
				}
				if points <= 0 {
					continue
				}
			}
			ixEntry = entry.Data
			cnts = SearchInBytes(ixEntry, "desc", wrds, 200)
			if cnts != nil && len(cnts.Counts) > 0 {
				for _, wCount := range cnts.Counts {
					points += int64(len(wCount))
				}
			}
			ixEntry = entry.Data
			cnts = SearchInBytes(ixEntry, "keys", wrds, 100)
			if cnts != nil && len(cnts.Counts) > 0 {
				for _, wCount := range cnts.Counts {
					points += int64(len(wCount))
				}
			}
			if points <= 0 {
				continue
			}
		}
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
		// Query content with provided prompt
		accuracy, points = GetItemQueryPoints(item, request, p, words, b)
		if points <= 0 {
			continue
		}
		// Final (optional) check
		if hasStockFilter {
			stockC, cncl = db.calculateItemStock(storeID, entry.uUID, "[main]")
			// Await answer
			stk = <-stockC
			if stk < request.MinStock {
				cncl()
				continue
			}
		} else {
			stk = 0.0
		}
		// Truncate item description
		if item.Description != "" {
			item.Description = EllipticalTruncate(item.Description, 500)
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
			Stock:     stk,
			Item:      item,
			Analytics: analytics,
			Accuracy:  accuracy,
		}
		queryResponse.Items = append(queryResponse.Items, container)
		// Stop if we have reached the maximum amount of results
		if len(queryResponse.Items) >= maxResults {
			cancel()
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
	c <- queryResponse
}

func GetItemQueryPoints(
	item *Item, query *ItemQuery, p *regexp.Regexp, words map[string]*QueryWord, b bool,
) (float64, int64) {
	points := int64(0)
	// Get all matches in selected fields
	var mAtts, mCats, mName, mDesc, mKeys, mBrand, mClrs []string
	// *** Categories ***
	if query.Fields == "" || strings.Contains(query.Fields, "cats") {
		if len(item.Categories) > 0 {
			var cats string
			// Since we might filter with multiple categories,
			// ... we need to avoid results not fitting all categories
			if len(query.Categories) > 0 {
				for _, cat := range item.Categories {
					cats += fmt.Sprintf("%s ", strings.ToLower(cat))
				}
				for _, cat := range query.Categories {
					if !strings.Contains(cats, cat) {
						return 0, 0
					}
				}
			} else {
				for _, cat := range item.Categories {
					cats += fmt.Sprintf("%s ", cat)
				}
			}
			mCats = p.FindAllString(cats, -1)
		}
	}
	// *** Brand ***
	if query.Fields == "" || strings.Contains(query.Fields, "brand") {
		if query.Brand != "" && strings.ToLower(item.Brand) != query.Brand {
			return 0, 0
		}
		mBrand = p.FindAllString(item.Brand, -1)
	}
	// *** Title ***
	if query.Fields == "" || strings.Contains(query.Fields, "title") {
		mName = p.FindAllString(item.Name, -1)
	}
	// *** Description ***
	if query.Fields == "" || strings.Contains(query.Fields, "desc") {
		mDesc = p.FindAllString(EllipticalTruncate(item.Description, 200), -1)
	}
	// *** Keywords ***
	if query.Fields == "" || strings.Contains(query.Fields, "keys") {
		mKeys = p.FindAllString(item.Keywords, -1)
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
	// Long spaghetti-guard
	if len(mKeys) < 1 && len(mDesc) < 1 && len(mName) < 1 && len(mBrand) < 1 && len(mAtts) < 1 && len(mCats) < 1 && len(mClrs) < 1 {
		// Return 0 if there were no matches
		return 0.0, 0
	}
	// Clean up
	for _, word := range words {
		word.B = !b
	}
	// Calculate points
	accuracy := 0.0
	var wrd *QueryWord
	var sml string
	for _, word := range mCats {
		sml = strings.ToLower(word)
		if words[sml] != nil {
			words[sml].B = b
		} else {
			words[sml] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
	for _, word := range mAtts {
		sml = strings.ToLower(word)
		if words[sml] != nil {
			words[sml].B = b
		} else {
			words[sml] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
	for _, word := range mName {
		sml = strings.ToLower(word)
		// Reward matches for the title as it means the most
		wrd = words[sml]
		if wrd != nil {
			words[sml].B = b
			points += wrd.Points * 2
		} else {
			words[sml] = &QueryWord{
				B:      b,
				Points: 1,
			}
			points += 2
		}
	}
	for _, word := range mDesc {
		sml = strings.ToLower(word)
		if words[sml] != nil {
			words[sml].B = b
		} else {
			words[sml] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
	for _, word := range mKeys {
		sml = strings.ToLower(word)
		// Reward matches for the keywords as they mean a lot
		wrd = words[sml]
		if wrd != nil {
			words[sml].B = b
			points += wrd.Points * 2
		} else {
			words[sml] = &QueryWord{
				B:      b,
				Points: 1,
			}
			points += 2
		}
	}
	for _, word := range mBrand {
		sml = strings.ToLower(word)
		if words[sml] != nil {
			words[sml].B = b
		} else {
			words[sml] = &QueryWord{
				B:      b,
				Points: 1,
			}
		}
	}
	for _, word := range mClrs {
		sml = strings.ToLower(word)
		if words[sml] != nil {
			words[sml].B = b
		} else {
			words[sml] = &QueryWord{
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
	accuracy = float64(points) / float64(len(words))
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

func (db *GoDB) handleGenerateIndex(mainDB *GoDB, connector *Connector) http.HandlerFunc {
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
		// Retrieve store
		storeResp, ok := mainDB.Read(StoreDB, storeID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		store := &Store{}
		err := json.Unmarshal(storeResp.Data, store)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if user.Username != store.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		wordQuery := r.URL.Query().Get("wrd")
		if wordQuery == "true" || wordQuery == "1" {
			_ = db.BuildQueryIndex(connector, storeID, user)
			return
		}
		db.createStoreFilterCache(storeID)
	}
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
		index := []string{"pid", "pid-cat", "pid-brand", "pid-manu", "pid-clrs"}
		_ = db.Delete(ItemDB, itemID, index)
		db.createStoreFilterCache(item.StoreUUID)
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
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
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
			bulkEditResults.Results[i] = db.doEditItem(w, user, &entry.Payload, entry.UUID, false)
		}
		render.JSON(w, r, bulkEditResults)
	}
}

func (db *GoDB) handleBulkItemStockModification(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		ts := TimeNowUnix()
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
		if store.Username != user.Username {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &BulkItemStockModificationRequest{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		modType := strings.ToLower(request.Type)
		modResults := make([]bool, len(request.Modifications))
		for i, entry := range request.Modifications {
			switch modType {
			case "set":
				modResults[i] = db.handleItemStockSet(storeID, entry, ts)
			case "add":
				modResults[i] = db.handleItemStockAdd(storeID, entry, ts)
			}
		}
		render.JSON(w, r, modResults)
	}
}

// handleItemStockSet adds a fixed stock update to the database
func (db *GoDB) handleItemStockSet(storeID string, entry ItemStockModification, ts int64) bool {
	if entry.Storage == "" {
		entry.Storage = "[main]"
	}
	// Store
	itemStock := ItemStock{
		UUID:        entry.UUID,
		TimeCreated: ts,
		Amount:      entry.Amount,
		Storage:     entry.Storage,
		Type:        "SET",
	}
	jsonEntry, err := json.Marshal(itemStock)
	if err != nil {
		return false
	}
	_, err = db.Insert(ItemDB, jsonEntry, map[string]string{
		"pid-uid-st": fmt.Sprintf("%s;%s;%s;%d", storeID, entry.UUID, entry.Storage, ts),
	})
	if err != nil {
		return false
	}
	return true
}

// handleItemStockAdd modifies the current stock of an item
// (e.g. a fixed stock update or starting with 0 if there has never been a stock update or modification)
func (db *GoDB) handleItemStockAdd(storeID string, entry ItemStockModification, ts int64) bool {
	if entry.Storage == "" {
		entry.Storage = "[main]"
	}
	// Store
	itemStock := ItemStock{
		UUID:        entry.UUID,
		TimeCreated: ts,
		Amount:      entry.Amount,
		Storage:     entry.Storage,
		Type:        "ADD",
	}
	jsonEntry, err := json.Marshal(itemStock)
	if err != nil {
		return false
	}
	_, err = db.Insert(ItemDB, jsonEntry, map[string]string{
		"pid-uid-st": fmt.Sprintf("%s;%s;%s;%d", storeID, entry.UUID, entry.Storage, ts),
	})
	if err != nil {
		return false
	}
	return true
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
	// _, txn := db.Get(ItemDB, itemID)
	txn := db.NewTransaction(true)
	defer txn.Discard()
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
		// First check if there is an up-to-date cached filter entry to use
		// We can save a lot of time (around 20 seconds) generating this filter report by using an existing one
		queryResponse := db.getStoreFilterCache(storeID)
		if queryResponse != nil {
			render.JSON(w, r, queryResponse)
			return
		}
		// There is no cached filter entry -> Create one
		queryResponse = db.createStoreFilterCache(storeID)
		if queryResponse != nil {
			render.JSON(w, r, queryResponse)
		} else {
			render.JSON(w, r, ItemFilters{
				Variations: make([]ItemVariation, 0),
				Colors:     make([]Category, 0),
				Categories: make([]string, 0),
				Brands:     make([]string, 0),
				MinCost:    0,
				MaxCost:    0,
				AvgCost:    0,
				Amount:     0,
				LastUpdate: TimeNowUnix(),
			})
		}
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
				fmt.Sprintf("%s;%s;", item.StoreUUID, strings.ToLower(category))
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
				fmt.Sprintf("%s;%s;", item.StoreUUID, strings.ToLower(color.Name))
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

func (db *GoDB) createStoreFilterCache(storeID string) *ItemFilters {
	// Retrieve all Item entries
	response, _, err := db.SSelect(ItemDB, map[string]string{
		"pid": storeID,
	}, nil, 30, 10, true, false)
	if err != nil {
		return nil
	}
	queryResponse := &ItemFilters{
		Variations: make([]ItemVariation, 0),
		Colors:     make([]Category, 0),
		Categories: make([]string, 0),
		Brands:     make([]string, 0),
		MinCost:    0,
		MaxCost:    0,
		AvgCost:    0,
		Amount:     0,
	}
	var item *Item
	var gross float64
	var count int
	var groupKey string
	cacheMap := map[string]bool{}
	var groupKeyExists bool
	var ix int
	for entry := range response {
		item = &Item{}
		err = json.Unmarshal(entry.Data, item)
		if err != nil {
			continue
		}
		queryResponse.Amount += 1
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
	// Did we find something?
	if queryResponse.Amount < 1 {
		// Store
		jsonEntry, err := json.Marshal(queryResponse)
		if err != nil {
			return nil
		}
		_, err = db.Insert(ItemDB, jsonEntry, map[string]string{
			"pid-filter": FIndex(storeID),
		})
		if err != nil {
			return nil
		}
		return queryResponse
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
	// Store
	queryResponse.LastUpdate = TimeNowUnix()
	jsonEntry, err := json.Marshal(queryResponse)
	if err != nil {
		return nil
	}
	_, err = db.Insert(ItemDB, jsonEntry, map[string]string{
		"pid-filter": FIndex(storeID),
	})
	if err != nil {
		return nil
	}
	return queryResponse
}

func (db *GoDB) getStoreFilterCache(storeID string) *ItemFilters {
	resp, err := db.Select(ItemDB, map[string]string{
		"pid-filter": FIndex(storeID),
	}, &SelectOptions{
		MaxResults: 1,
		Page:       0,
		Skip:       0,
	})
	if err != nil {
		return nil
	}
	response := <-resp
	if len(response) < 1 {
		return nil
	}
	filters := &ItemFilters{}
	err = json.Unmarshal(response[0].Data, filters)
	if err != nil {
		return nil
	}
	return filters
}

func (db *GoDB) calculateItemStock(storeID, itemID, storageUnit string) (chan float64, context.CancelFunc) {
	c := make(chan float64)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		defer func() {
			if r := recover(); r != nil {
				return
			}
		}()
		go db.doCalcItemStock(ctx, c, storeID, itemID, storageUnit)
	}()
	return c, cancel
}

func (db *GoDB) doCalcItemStock(ctx context.Context, c chan float64, storeID, itemID, storageUnit string) {
	defer close(c)
	// Start retrieving stock entries
	response, cancel, err := db.SSelect(ItemDB, map[string]string{
		"pid-uid-st": fmt.Sprintf("%s;%s;%s;", storeID, itemID, storageUnit),
	}, nil, -1, 100, true, false)
	if err != nil {
		c <- 0.0
		return
	}
	// We will filter the storage unit until we have reached a "SET" type stock entry
	// ... or there are no more stock entries
	stocks := make([]*ItemStock, 0)
	var stock *ItemStock
	for entry := range response {
		stock = &ItemStock{}
		err = json.Unmarshal(entry.Data, stock)
		if err != nil {
			continue
		}
		// Add stock amount to current stock amount
		stocks = append(stocks, stock)
		// Exit upon reaching "SET" type stock
		if stock.Type == "SET" {
			cancel()
			break
		}
	}
	if len(stocks) < 1 {
		c <- 0.0
		return
	}
	// Sort stock entries by date (highest to lowest as timestamp is UNIX int64)
	// ... to ensure chronological order
	sort.SliceStable(
		stocks, func(i, j int) bool {
			return stocks[i].TimeCreated > stocks[j].TimeCreated
		},
	)
	// We will now calculate the stock
	// Example:
	//     ADD  5.0
	//     ADD  3.0
	//     ADD -7.0
	//     SET  9.0
	// The calculated stock in this example would be 10, because:
	//     9 + (-7) =  2
	//     2 +   3  =  5
	//     5 +   5  = 10 -> return 10
	// It also works the other way around, the way we have to calculate anyway:
	//     5 +   3  =  8
	//     8 + (-7) =  1
	//     1 +   9  = 10 -> return 10
	// Since a "SET" type stock entry is assumed to respect previous stock updates,
	// ... we simply exit to allow for infinite stock entries reaching far into the past
	stk := 0.0
	lts := int64(-1)
	for _, stock = range stocks {
		select {
		case <-ctx.Done():
			c <- stk
			return
		default:
		}
		if lts == -1 {
			lts = stock.TimeCreated
		}
		stk += stock.Amount
		if stock.Type == "SET" {
			break
		}
	}
	c <- stk
}

// BuildQueryIndex iterates over all items of a store, generating an index of words, linked to items.
// When a user searches for items, the query will also be split into words
// ...and then matched against the word index.
//
// Since the DB is sorted and doesn't work with substring queries (it's full match only)
// ...we need to find all complete words that contain the substring.
//
// With wheels as an example, the substring "rift" would lead to "drift".
// To further enhance the query speed, the substrings successfully matched to complete words
// ...will be indexed, too, so we can find "drift" almost instantly when searching for "rift".
func (db *GoDB) BuildQueryIndex(connector *Connector, storeID string, user *User) error {
	// Retrieve all Item entries
	response, _, err := db.SSelect(ItemDB, map[string]string{
		"pid": storeID,
	}, nil, 120, 0, true, false)
	if err != nil {
		return nil
	}
	// wordCache maps slices of item UUIDs to words
	// As soon as a slice gets too big, the word will get suffixed and inserted as a new one
	wordCache := make(map[string][]string)
	var ixEntry []byte
	var field []byte
	count := 0
	maxCount := 0
	// Retrieve connector entry of requester, so we can inform them about the progress!
	connector.SessionsMu.RLock()
	sesh, hasSesh := connector.Sessions.Get(user.Username)
	connector.SessionsMu.RUnlock()
	for entry := range response {
		count += 1
		maxCount += 1
		// (1/2) Extract words from the title
		ixEntry = entry.Data
		field = GetByteValueFromField(ixEntry, []byte("\"t\":"), 100)
		if len(field) > 0 {
			wordCache = addWordsToCache(wordCache, entry, field)
		}
		// (2/2) Extract words from the description
		ixEntry = entry.Data
		field = GetByteValueFromField(ixEntry, []byte("\"desc\":"), 200)
		if len(field) > 0 {
			if len(field) > 0 {
				wordCache = addWordsToCache(wordCache, entry, field)
			}
		}
		if count >= 1_000 {
			count = 0
			if hasSesh {
				_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
					Type:          "[s:storeix]",
					Action:        "log",
					ReferenceUUID: "",
					Username:      user.Username,
					Message:       fmt.Sprint("m12Items >>> (1/3) Generating word cache size ", len(wordCache), " entries ", maxCount),
				})
			}
			// Don't think this helps? My single core server says otherwise!
			timer := time.NewTimer(time.Millisecond * 500)
			<-timer.C
		}
		if maxCount >= 100_000 {
			break
		}
	}
	timer := time.NewTimer(time.Second * 2)
	<-timer.C
	connector.SessionsMu.RLock()
	sesh, hasSesh = connector.Sessions.Get(user.Username)
	connector.SessionsMu.RUnlock()
	if hasSesh {
		_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
			Type:          "[s:storeix]",
			Action:        "log",
			ReferenceUUID: "",
			Username:      user.Username,
			Message:       fmt.Sprint("m12Items >>> (1/3) DONE size ", len(wordCache), " entries ", maxCount),
		})
		_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
			Type:          "[s:storeix]",
			Action:        "log",
			ReferenceUUID: "",
			Username:      user.Username,
			Message:       fmt.Sprint("m12Items >>> (2/3) Removing previous word caches"),
		})
	}
	// Remove any word indices that had been saved on the DB so far
	// These custom indices are suffixed by the store id
	customKey := fmt.Sprintf("wrd-%s", storeID)
	err = db.SUpdate(ItemDB, db.NewTransaction(true), []byte("WKRG:INIT"), map[string]string{
		customKey: "",
	})
	if err != nil {
		return err
	}
	timer = time.NewTimer(time.Second * 2)
	<-timer.C
	connector.SessionsMu.RLock()
	sesh, hasSesh = connector.Sessions.Get(user.Username)
	connector.SessionsMu.RUnlock()
	if hasSesh {
		_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
			Type:          "[s:storeix]",
			Action:        "log",
			ReferenceUUID: "",
			Username:      user.Username,
			Message:       fmt.Sprint("m12Items >>> (2/3) DONE"),
		})
	}
	// Turn the results into indices and save them all!
	count = 0
	maxCount = 0
	for wrd, ids := range wordCache {
		if len(ids) < 1 {
			continue
		}
		count += 1
		maxCount += 1
		uidStr := ""
		for _, id := range ids {
			uidStr += FIndex(id)
		}
		err = db.SInsert(ItemDB, []byte(uidStr), map[string]string{
			customKey: FIndex(wrd),
		})
		if count >= 250 {
			count = 0
			if hasSesh {
				_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
					Type:          "[s:storeix]",
					Action:        "log",
					ReferenceUUID: "",
					Username:      user.Username,
					Message:       fmt.Sprint("m12Items >>> (3/3) Inserting word cache entries ", maxCount),
				})
			}
			timer = time.NewTimer(time.Millisecond * 500)
			<-timer.C
		}
	}
	connector.SessionsMu.RLock()
	sesh, hasSesh = connector.Sessions.Get(user.Username)
	connector.SessionsMu.RUnlock()
	if hasSesh {
		_ = WSSendJSON(sesh.Conn, sesh.Ctx, &ConnectorMsg{
			Type:          "[s:storeix]",
			Action:        "log",
			ReferenceUUID: "",
			Username:      user.Username,
			Message:       fmt.Sprint("m12Items >>> (3/3) DONE size ", len(wordCache)),
		})
	}
	return nil
}

func addWordsToCache(wordCache map[string][]string, entry *EntryResponse, field []byte) map[string][]string {
	var ok bool
	var str string
	var lst []string
	stops := "a or the these this that those else other der die das um am ,.-!\"§$%&/\\()=?[]{}@€°^+#´`"
	for _, fld := range bytes.Fields(field) {
		str = strings.ToLower(string(fld))
		// Check for a stop word or special characters
		if strings.Contains(stops, str) {
			continue
		}
	wkrgCommonW:
		lst, ok = wordCache[str]
		if !ok {
			wordCache[str] = []string{entry.uUID}
			continue
		}
		if len(lst) < 256 {
			if !slices.Contains(lst, entry.uUID) {
				wordCache[str] = append(wordCache[str], entry.uUID)
			}
		} else {
			if len(str) > 200 {
				continue
			}
			// Too many entries, try again with a suffixed word
			str += "0"
			// Dirty jump!!! He used a dirty jump!!!
			goto wkrgCommonW
		}
	}
	return wordCache
}
