package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"math"
	"net/http"
	"slices"
	"strings"
)

const FinanceDB = "m15"

func (db *GoDB) ProtectedFinanceEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth, mainDB *GoDB, connector *Connector,
) {
	r.Route("/finance/private", func(r chi.Router) {
		r.Route("/collection", func(r chi.Router) {
			r.Post("/create", db.handleFinanceCollectionCreate())
			r.Get("/join/{collectionID}", db.handleFinanceCollectionJoin(connector))
			r.Get("/view/{collectionID}", db.handleFinanceCollectionViewTransactions())
			r.Get("/delete/{collectionID}", db.handleFinanceCollectionDelete())
		})
		r.Route("/trx", func(r chi.Router) {
			r.Post("/create/{collectionID}", db.handleFinanceTransactionCreate(mainDB))
			r.Post("/sign/{trxID}", db.handleFinanceTransactionSign(mainDB))
			r.Get("/cancel/{trxID}", db.handleFinanceTransactionDelete())
		})
	})
}

type FinanceCollection struct {
	Name          string   `json:"t"`
	Description   string   `json:"desc"`
	Keywords      string   `json:"keys"`
	TimeCreated   string   `json:"ts"`
	TimeFinished  string   `json:"tsd"`
	IsFinished    bool     `json:"done"`
	Username      string   `json:"usr"`
	Collaborators []string `json:"coll"`
	BannerURL     string   `json:"burl"`
}

func (a *FinanceCollection) Bind(_ *http.Request) error {
	if a.Name == "" && a.Description == "" {
		return errors.New("missing name or description")
	}
	return nil
}

type FinanceTransaction struct {
	CollectionUUID string               `json:"pid"`
	PreviousUUID   string               `json:"prev"`
	Timestamp      string               `json:"ts"`
	UsernameFrom   string               `json:"from"`
	UsernameTo     string               `json:"to"`
	Type           string               `json:"type"`
	Signature      string               `json:"sig"`
	Unit           string               `json:"unit"`
	Value          float64              `json:"val"`
	BlockChainHash string               `json:"hash"`
	Distribution   []FinanceUserSummary `json:"dist"`
	Comment        string               `json:"comment"`
	Category       string               `json:"cat"`
}

func (trx *FinanceTransaction) Bind(_ *http.Request) error {
	if trx.Type == "" {
		return errors.New("missing type")
	}
	return nil
}

type FinanceSign struct {
	Pass string `json:"pass"`
}

func (a *FinanceSign) Bind(_ *http.Request) error {
	if a.Pass == "" {
		return errors.New("missing pass")
	}
	return nil
}

type FinanceOverview struct {
	Collection   FinanceCollection    `json:"collection"`
	Transactions []FinanceTransaction `json:"transactions"`
	Summary      []FinanceUserSummary `json:"summary"`
	Compensation []FinanceUserSummary `json:"compensation"`
}

func (a *FinanceOverview) Bind(_ *http.Request) error {
	return nil
}

type FinanceUserSummary struct {
	UsernameFrom string  `json:"from"`
	UsernameTo   string  `json:"to"`
	Unit         string  `json:"unit"`
	Value        float64 `json:"val"`
	Ratio        float64 `json:"ratio"`
	TotalIncome  float64 `json:"total_income"`
	TotalPayment float64 `json:"total_payment"`
}

func (a *FinanceUserSummary) Bind(_ *http.Request) error {
	return nil
}

func (db *GoDB) handleFinanceCollectionCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &FinanceCollection{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Sanitize
		request.Username = user.Username
		// Collection collaborators cannot be set
		request.Collaborators = []string{user.Username}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(FinanceDB, jsonEntry, map[string]string{
			"usr": fmt.Sprintf("%s;", request.Username),
		})
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleFinanceCollectionViewTransactions() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		collectionID := chi.URLParam(r, "collectionID")
		if collectionID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		var ok bool
		// Get Collection
		resp, ok := db.Read(FinanceDB, collectionID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		collection := &FinanceCollection{}
		err := json.Unmarshal(resp.Data, collection)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to view this Collection
		if collection.Username != user.Username &&
			!slices.Contains(collection.Collaborators, user.Username) {
			// Not part of this collection
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		summary := map[string]FinanceUserSummary{}
		for _, collaborator := range collection.Collaborators {
			summary[collaborator] = FinanceUserSummary{
				UsernameFrom: collaborator,
				Value:        0.0,
				TotalIncome:  0.0,
				TotalPayment: 0.0,
			}
		}
		overview := &FinanceOverview{
			Collection:   *collection,
			Transactions: []FinanceTransaction{},
			Summary:      []FinanceUserSummary{},
			Compensation: []FinanceUserSummary{},
		}
		respTrx, errTrx := db.Select(FinanceDB,
			map[string]string{"pid": FIndex(collectionID)}, nil,
		)
		if errTrx != nil {
			// Respond to client
			render.JSON(w, r, overview)
			return
		}
		responseTrx := <-respTrx
		if len(responseTrx) < 1 {
			// Respond to client
			render.JSON(w, r, overview)
			return
		}
		var tmpSummary FinanceUserSummary
		var found bool
		// Iterate over all transactions
		for _, rsp := range responseTrx {
			rspT := &FinanceTransaction{}
			err = json.Unmarshal(rsp.Data, rspT)
			if err != nil {
				continue
			}
			overview.Transactions = append(overview.Transactions, *rspT)
			// Count total income and payment
			usrCount := 0
			if rspT.UsernameFrom != "" {
				usrCount += 1
				tmpSummary, ok = summary[rspT.UsernameFrom]
				if ok {
					tmpSummary.TotalPayment += rspT.Value
					summary[rspT.UsernameFrom] = tmpSummary
				}
			}
			if rspT.UsernameTo != "" {
				usrCount += 1
				tmpSummary, ok = summary[rspT.UsernameTo]
				if ok {
					tmpSummary.TotalIncome += rspT.Value
					summary[rspT.UsernameTo] = tmpSummary
				}
			}
			// If this is a directional payment between to users, add a negative compensation to
			// ... balance out any open compensations
			if usrCount == 2 {
				// Do we know this directional payment already?
				found = false
				for k, userSummary := range overview.Compensation {
					if userSummary.UsernameFrom == rspT.UsernameFrom &&
						userSummary.UsernameTo == rspT.UsernameTo {
						found = true
						userSummary.Value -= rspT.Value
						overview.Compensation[k] = userSummary
						break
					}
				}
				if !found {
					// Add new directional payment
					overview.Compensation = append(overview.Compensation, FinanceUserSummary{
						UsernameFrom: rspT.UsernameFrom,
						UsernameTo:   rspT.UsernameTo,
						Unit:         rspT.Unit,
						Value:        rspT.Value * -1,
						Ratio:        -1,
					})
				}
			}
			// Iterate over the distribution of the current transaction
			// ... to calculate directional payment (who owes whom)
			for _, dist := range rspT.Distribution {
				// Check for directional payment (from and to a user)
				if dist.UsernameFrom == "" || dist.UsernameTo == "" {
					continue
				}
				// Do we know this directional payment already?
				found = false
				for k, userSummary := range overview.Compensation {
					if userSummary.UsernameFrom == dist.UsernameFrom &&
						userSummary.UsernameTo == dist.UsernameTo {
						found = true
						userSummary.Value += dist.Value
						overview.Compensation[k] = userSummary
						break
					}
				}
				if found {
					continue
				}
				// Add new directional payment
				overview.Compensation = append(overview.Compensation, FinanceUserSummary{
					UsernameFrom: dist.UsernameFrom,
					UsernameTo:   dist.UsernameTo,
					Unit:         rspT.Unit,
					Value:        dist.Value,
					Ratio:        dist.Ratio,
				})
			}
		}
		for _, userSummary := range summary {
			overview.Summary = append(overview.Summary, userSummary)
		}
		// Respond to client
		render.JSON(w, r, overview)
	}
}

func (db *GoDB) handleFinanceCollectionJoin(connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		collectionID := chi.URLParam(r, "collectionID")
		if collectionID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Collection
		resp, txn := db.Get(FinanceDB, collectionID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		collection := &FinanceCollection{}
		err := json.Unmarshal(resp.Data, collection)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user is already part of this collection
		for i := 0; i < len(collection.Collaborators); i++ {
			if collection.Collaborators[i] == user.Username {
				return
			}
		}
		// Notify users and request a reload of the data
		usersToNotify := slices.Clone(collection.Collaborators)
		usersToNotify = append(usersToNotify, collection.Username)
		// Add user
		collection.Collaborators = append(collection.Collaborators, user.Username)
		jsonEntry, err := json.Marshal(collection)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(FinanceDB, txn, collectionID, jsonEntry, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		for _, username := range usersToNotify {
			go db.notifyCollectionCollaborator(
				connector,
				collectionID,
				"User joined your Finance account",
				fmt.Sprintf("%s has joined the account %s", user.DisplayName, collection.Name),
				username,
				true)
		}
		return
	}
}

func (db *GoDB) handleFinanceCollectionDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		collectionID := chi.URLParam(r, "collectionID")
		if collectionID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Collection
		resp, txn := db.Get(FinanceDB, collectionID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		collection := &FinanceCollection{}
		err := json.Unmarshal(resp.Data, collection)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to delete this Collection
		if collection.Username == user.Username {
			txn.Discard()
			err = db.Delete(FinanceDB, collectionID, []string{"usr", "coll"})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			txn.Discard()
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
}

func (db *GoDB) handleFinanceTransactionCreate(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		collectionID := chi.URLParam(r, "collectionID")
		if collectionID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &FinanceTransaction{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve last saved transaction to remember its UUID as the previous UUID
		resp, err := db.Select(FinanceDB,
			map[string]string{
				"pid": FIndex(request.CollectionUUID),
			}, &SelectOptions{
				MaxResults: 1,
				Page:       0,
				Skip:       0,
			},
		)
		// Is there a previous entry?
		if err == nil {
			response := <-resp
			if len(response) > 0 {
				previous := &FinanceTransaction{}
				err = json.Unmarshal(response[0].Data, previous)
				if err == nil {
					// Remember previous UUID
					request.PreviousUUID = response[0].uUID
				}
			}
		}
		// Get Collection
		respC, ok := db.Read(FinanceDB, collectionID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		coll := &FinanceCollection{}
		err = json.Unmarshal(respC.Data, coll)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Sanitize
		// Since payments/income is directional we only need
		// ... absolute values to count
		request.Value = math.Abs(request.Value)
		if strings.TrimSpace(request.Comment) != "" {
			// Limit comment to around 1000 symbols
			request.Comment = EllipticalTruncate(
				request.Comment, 1_000)
		}
		if strings.TrimSpace(request.Category) != "" {
			// Limit category to around 100 symbols
			request.Category = EllipticalTruncate(request.Category, 100)
		}
		if request.Unit == "" {
			request.Unit = "EUR"
		}
		for _, dist := range request.Distribution {
			if dist.Unit == "" {
				dist.Unit = request.Unit
			}
			// Since payments/income is directional we only need
			// ... absolute values to count
			dist.Value = math.Abs(dist.Value)
			dist.Ratio = math.Abs(dist.Ratio)
		}
		request.Timestamp = TimeNowIsoString()
		sig := request.Signature
		request.GenerateHashes(db)
		if request.UsernameFrom == user.Username && sig != "" {
			request.SignTransaction(mainDB, user.Username, request.Signature)
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(FinanceDB, jsonEntry, map[string]string{
			"pid": fmt.Sprintf("%s", collectionID),
		})
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleFinanceTransactionSign(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		trxID := chi.URLParam(r, "trxID")
		if trxID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &FinanceSign{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Get Transaction
		resp, txn := db.Get(FinanceDB, trxID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		trx := &FinanceTransaction{}
		err := json.Unmarshal(resp.Data, trx)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to sign this Collection
		if trx.UsernameFrom == user.Username {
			trx.SignTransaction(mainDB, user.Username, request.Pass)
			jsonEntry, err := json.Marshal(trx)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(FinanceDB, txn, trxID, jsonEntry, nil)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			txn.Discard()
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
}

func (db *GoDB) handleFinanceTransactionDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		trxID := chi.URLParam(r, "trxID")
		if trxID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Transaction
		resp, txn := db.Get(FinanceDB, trxID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		trx := &FinanceTransaction{}
		err := json.Unmarshal(resp.Data, trx)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to cancel this Collection
		if trx.UsernameFrom != user.Username {
			txn.Discard()
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// We can only cancel the first or last transaction made
		// ... for this collection. Otherwise, we would break the chain
		respT, err := db.Select(FinanceDB,
			map[string]string{
				"pid": FIndex(trx.CollectionUUID),
			}, &SelectOptions{
				MaxResults: 1,
				Page:       0,
				Skip:       0,
			},
		)
		// Is there a previous entry?
		if err == nil {
			response := <-respT
			if len(response) > 0 {
				if trxID != response[0].uUID {
					// This is not the last transaction, so we return
					http.Error(w, http.StatusText(http.StatusConflict), http.StatusConflict)
					return
				}
			}
		}
		// Cancel the transaction as it's either the first or last transaction
		txn.Discard()
		err = db.Delete(FinanceDB, trxID, []string{"pid"})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (trx *FinanceTransaction) GenerateHashes(rapidDB *GoDB) bool {
	// Retrieve previous block entry if there is one
	var err error
	var previousStr []byte
	if trx.PreviousUUID != "" {
		respT, txnT := rapidDB.Get(FinanceDB, trx.PreviousUUID)
		if txnT == nil {
			return false
		}
		defer txnT.Discard()
		trxT := &FinanceTransaction{}
		err = json.Unmarshal(respT.Data, trxT)
		if err != nil {
			return false
		}
		previousStr, err = json.Marshal(trxT)
		if err != nil {
			return false
		}
	} else {
		previousStr = []byte{}
	}
	trx.Signature = ""
	trx.BlockChainHash = ""
	// Generate blockchain hash
	var trxStr []byte
	trxStr, err = json.Marshal(trx)
	if err != nil {
		return false
	}
	trxHsh := sha256.New()
	trxHsh.Write(trxStr)
	prevHsh := sha256.New()
	prevHsh.Write(previousStr)
	trx.BlockChainHash = fmt.Sprintf("%x;%x", trxHsh.Sum(nil), prevHsh.Sum(nil))
	return true
}

func (trx *FinanceTransaction) SignTransaction(mainDB *GoDB, user, pass string) bool {
	var err error
	// Check if user exists in the database then compare passwords
	resp, err := mainDB.Select(UserDB,
		map[string]string{
			"usr": FIndex(user),
		}, &SelectOptions{
			MaxResults: 1,
			Page:       0,
			Skip:       0,
		},
	)
	if err != nil {
		return false
	}
	response := <-resp
	if len(response) < 1 {
		return false
	}
	userFromDB := &User{}
	err = json.Unmarshal(response[0].Data, userFromDB)
	if err != nil {
		return false
	}
	// Retrieve hashed password from db user
	credPass := userFromDB.PassHash
	// Hash password from request
	h := sha256.New()
	h.Write([]byte(pass))
	userPass := fmt.Sprintf("%x", h.Sum(nil))
	// Compare both passwords
	if subtle.ConstantTimeCompare([]byte(userPass), []byte(credPass)) != 1 {
		return false
	}
	// The Signature consists of the...
	// * username,
	// * password hash,
	// * transaction hash including blockchain hash
	// * timestamp
	sig := sha256.New()
	sig.Write([]byte(fmt.Sprintf("%s;%s;%s;%s", user, userPass, trx.BlockChainHash, trx.Timestamp)))
	// Signature gets inserted with name as prefix for usability (who signed it)
	trx.Signature = fmt.Sprintf("%s;%x", user, sig.Sum(nil))
	return true
}

func (db *GoDB) notifyCollectionCollaborator(
	connector *Connector, collectionID, title, message, username string, requestReload bool) {
	notification := &Notification{
		Title:             title,
		Description:       message,
		Type:              "info",
		TimeCreated:       TimeNowIsoString(),
		RecipientUsername: username,
	}
	jsonNotification, err := json.Marshal(notification)
	if err != nil {
		return
	}
	notificationUUID, err := db.Insert(NotifyDB, jsonNotification, map[string]string{
		"usr": FIndex(username),
	})
	if err != nil {
		return
	}
	// Now send a message via the connector
	session, ok := connector.Sessions.Get(username)
	if !ok {
		return
	}
	cMSG := &ConnectorMsg{
		Type:          "[s:NOTIFICATION]",
		Action:        "info",
		ReferenceUUID: notificationUUID,
		Username:      username,
		Message:       message,
	}
	_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	if requestReload {
		cMSG = &ConnectorMsg{
			Type:          "[s:CHANGE>FINANCE]",
			Action:        "reload",
			ReferenceUUID: collectionID,
			Username:      username,
		}
		_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	}
}
