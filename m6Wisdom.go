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
	"strconv"
	"strings"
	"time"
)

const WisdomDB = "m6"

type Wisdom struct {
	Name                 string          `json:"t"`
	Description          string          `json:"desc"`
	Keywords             string          `json:"keys"`
	CopyContent          string          `json:"copy"`
	Author               string          `json:"usr"`
	Type                 string          `json:"type"`
	TimeCreated          string          `json:"ts"`
	TimeFinished         string          `json:"tsd"`
	TimeDue              string          `json:"due"`
	TimeDueEnd           string          `json:"duet"`
	IsFinished           bool            `json:"done"`
	KnowledgeUUID        string          `json:"pid"`
	Categories           []Category      `json:"cats"`
	ReferenceUUID        string          `json:"ref"` // References another Wisdom e.g. Comment referencing Answer
	AnalyticsUUID        string          `json:"ana"` // Views, likes etc. will be stored in a separate database
	IsPublic             bool            `json:"pub"`
	Collaborators        []string        `json:"coll"`
	ThumbnailURL         string          `json:"iurl"`
	ThumbnailAnimatedURL string          `json:"iurla"`
	BannerURL            string          `json:"burl"`
	BannerAnimatedURL    string          `json:"burla"`
	RowIndex             float64         `json:"row"`
	Chapters             []WisdomChapter `json:"chapters"`
}

type WisdomContainer struct {
	UUID string `json:"uid"`
	*Wisdom
	*Analytics
	Accuracy       float64            `json:"accuracy"`
	Replies        []*WisdomContainer `json:"replies"`
	HasMoreReplies bool               `json:"moreReplies"`
}

type WisdomChapter struct {
	UUID        string     `json:"uid"`
	Name        string     `json:"t"`
	Author      string     `json:"usr"`
	Keywords    string     `json:"keys"`
	Categories  []Category `json:"cats"`
	TimeCreated string     `json:"ts"`
	Index       int        `json:"index"`
}

type BoxesContainer struct {
	Boxes []*BoxContainer `json:"boxes"`
}

type BoxContainer struct {
	Box   *WisdomContainer   `json:"box"`
	Tasks []*WisdomContainer `json:"tasks"`
}

type QueryResponse struct {
	TimeSeconds     float64            `json:"respTime"`
	Lessons         []*WisdomContainer `json:"lessons"`
	Replies         []*WisdomContainer `json:"replies"`
	Questions       []*WisdomContainer `json:"questions"`
	Answers         []*WisdomContainer `json:"answers"`
	Boxes           []*WisdomContainer `json:"boxes"`
	Tasks           []*WisdomContainer `json:"tasks"`
	Courses         []*WisdomContainer `json:"courses"`
	Posts           []*WisdomContainer `json:"posts"`
	Proposals       []*WisdomContainer `json:"proposals"`
	Misc            []*WisdomContainer `json:"misc"`
	ReferenceWisdom *WisdomContainer   `json:"ref"`
}

type WisdomQuery struct {
	Query                string `json:"query"`
	Type                 string `json:"type"`
	Fields               string `json:"fields"`
	State                string `json:"state"`
	MaxResults           int    `json:"results"`
	WithReplies          bool   `json:"withReply"`
	NoSort               bool   `json:"noSort"`
	MaxDescriptionLength int    `json:"descLen"`
}

type QueryWord struct {
	B      bool
	Points int64
}

type TaskMoveRequest struct {
	ToUUID   string  `json:"toId"`
	RowIndex float64 `json:"row"`
}

type TopContributors struct {
	Contributors []*ContributorStat `json:"contributors"`
}

type ContributorStat struct {
	Username    string `json:"usr"`
	WisdomCount int    `json:"wisdomCount"`
}

type WisdomModification struct {
	Type     string `json:"type"`
	Field    string `json:"field"`
	NewValue string `json:"new"`
}

type WisdomReminderRequest struct {
	Title               string                  `json:"t"`
	Description         string                  `json:"desc"`
	Topic               string                  `json:"topic"`
	Recipients          []NotificationRecipient `json:"recipients"`
	TriggerDateTime     string                  `json:"due"`
	TriggerDelay        string                  `json:"delay"`
	IsReoccurring       bool                    `json:"periodic"`
	ReoccurringAmount   int64                   `json:"amount"`
	ReoccurringInterval string                  `json:"interval"`
}

type WisdomKeywordList struct {
	Keywords []string `json:"keys"`
}

func (db *GoDB) ProtectedWisdomEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
	mainDB *GoDB, connector *Connector,
) {
	r.Route("/wisdom/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/create", db.handleWisdomCreate(mainDB, connector))
		r.Post("/edit/{wisdomID}", db.handleWisdomEdit(mainDB, connector))
		r.Post("/move/{wisdomID}", db.handleWisdomMove(mainDB, connector))
		r.Post("/reply", db.handleWisdomReply(mainDB, connector))
		r.Post("/react/{wisdomID}", db.handleWisdomReaction(mainDB, connector))
		r.Post("/query/{knowledgeID}", db.handleWisdomQuery(mainDB))
		r.Post("/mod/{wisdomID}", db.handleWisdomModification(mainDB, connector))
		r.Post("/reminder/{wisdomID}", db.handleWisdomReminderRequest(mainDB))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/get/{wisdomID}", db.handleWisdomGet(mainDB))
		r.Get("/delete/{wisdomID}", db.handleWisdomDelete(mainDB, connector))
		r.Get("/finish/{wisdomID}", db.handleWisdomFinish(mainDB, connector))
		r.Get("/tasks/{knowledgeID}", db.handleWisdomGetTasks(mainDB))
		r.Get("/contributors/{knowledgeID}", db.handleGetContributors(mainDB))
		r.Get("/investigate/{wisdomID}", db.handleWisdomInvestigate(mainDB))
		r.Get("/accept/{wisdomID}", db.handleWisdomAcceptAnswer(mainDB, connector))
		r.Get("/meta/{knowledgeID}", db.handleWisdomMetaRetrieval(mainDB))
		r.Get("/export/{wisdomID}", db.handleWisdomExport(mainDB))
	})
}

func (db *GoDB) handleWisdomGet(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Read(WisdomDB, wisdomID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		wisdom := &Wisdom{}
		err := json.Unmarshal(response.Data, wisdom)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// If Wisdom is not public, check member and read right
		canRead, _ := CheckWisdomAccess(
			user, wisdom, mainDB, db, r)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Is there an analytics entry?
		analytics := &Analytics{}
		if wisdom.AnalyticsUUID != "" {
			anaBytes, txn := db.Get(AnaDB, wisdom.AnalyticsUUID)
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
							_ = db.Update(AnaDB, txn, wisdom.AnalyticsUUID, jsonAna, map[string]string{})
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
				// Insert analytics while returning its UUID to the wisdom for reference
				wisdomBytes, txnWis := db.Get(WisdomDB, wisdomID)
				defer txnWis.Discard()
				wisdom.AnalyticsUUID, err = db.Insert(AnaDB, jsonAna, map[string]string{})
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				// Update wisdom
				wisdomJson, err := json.Marshal(wisdom)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(WisdomDB, txnWis, wisdomBytes.uUID, wisdomJson, map[string]string{})
			}
		}
		container := &WisdomContainer{
			UUID:      wisdomID,
			Wisdom:    wisdom,
			Analytics: analytics,
		}
		render.JSON(w, r, container)
	}
}

func (a *Wisdom) Bind(_ *http.Request) error {
	if a.Name == "" && a.Description == "" {
		return errors.New("missing name or description")
	}
	if a.KnowledgeUUID == "" {
		return errors.New("missing knowledge id")
	}
	if a.Type == "" {
		return errors.New("missing type")
	}
	return nil
}

func (a *WisdomQuery) Bind(_ *http.Request) error {
	if a.Query == "" {
		return errors.New("missing query")
	}
	return nil
}

func (a *TaskMoveRequest) Bind(_ *http.Request) error {
	return nil
}

func (a *WisdomModification) Bind(_ *http.Request) error {
	if a.Type == "" {
		return errors.New("missing type")
	}
	if a.Field == "" {
		return errors.New("missing field")
	}
	return nil
}

func (a *WisdomReminderRequest) Bind(_ *http.Request) error {
	if a.Title == "" && a.Description == "" {
		return errors.New("missing one of title and description")
	}
	if a.ReoccurringAmount < 0 {
		a.ReoccurringAmount = 0
	} else {
		// Validate interval (only m and h are allowed)
		if a.ReoccurringInterval != "" {
			l := len(a.ReoccurringInterval)
			if l < 2 {
				return errors.New("invalid interval")
			}
			unit := a.ReoccurringInterval[l-1 : l]
			if unit != "m" && unit != "h" {
				return errors.New("interval unit needs to be one of m or h")
			}
			if unit == "m" {
				i, err := strconv.ParseInt(a.ReoccurringInterval[0:l-1], 10, 64)
				if err != nil {
					return errors.New("invalid interval")
				}
				if i < 1 {
					a.ReoccurringInterval = "1m"
				}
			}
		}
	}
	return nil
}

func (db *GoDB) handleWisdomCreate(mainDB *GoDB, connector *Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &Wisdom{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request.Type = strings.ToLower(request.Type)
		request.Type = strings.TrimSpace(request.Type)
		if request.Type == "reply" || request.Type == "answer" {
			http.Error(w, "use reply endpoint for reply or answer",
				http.StatusBadRequest)
			return
		}
		if request.Type != "lesson" &&
			request.Type != "question" &&
			request.Type != "box" &&
			request.Type != "task" &&
			request.Type != "post" &&
			request.Type != "course" &&
			request.Type != "proposal" {
			http.Error(w, "type must be one of lesson or answer or box or task or post or course or proposal",
				http.StatusBadRequest)
			return
		}
		if request.Type == "task" || request.Type == "proposal" {
			if request.ReferenceUUID == "" {
				http.Error(w, "refID cannot be empty for tasks or proposals",
					http.StatusBadRequest)
				return
			}
		}
		// Check member and write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, request.KnowledgeUUID, mainDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Sanitize
		request.Author = user.Username
		request.TimeCreated = TimeNowIsoString()
		request.Keywords = strings.ToLower(request.Keywords)
		if request.Collaborators == nil {
			request.Collaborators = make([]string, 0)
		}
		if request.Categories == nil {
			request.Categories = make([]Category, 0)
		}
		if request.Type == "question" {
			if request.Keywords != "" {
				request.Keywords += ","
			}
			request.Keywords += "question"
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(WisdomDB, jsonEntry, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s;%s", request.KnowledgeUUID, request.Type),
			"refID-state":      fmt.Sprintf("%s;%t", request.ReferenceUUID, request.IsFinished),
		})
		if request.Type == "task" {
			_, txn := db.Get(WisdomDB, uUID)
			db.rearrangeTasks(request, uUID)
			jsonEntry, err = json.Marshal(request)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(WisdomDB, txn, uUID, jsonEntry, nil)
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
		go db.NotifyTaskChange(user, request, uUID, mainDB, connector)
		if request.Type == "post" {
			go db.NotifyMembersCustomMessage(
				"New Post",
				fmt.Sprintf("Go see %s's new post: %s!", request.Author, request.Name),
				user,
				request,
				uUID,
				mainDB,
				connector,
			)
		}
	}
}

func (db *GoDB) handleWisdomEdit(mainDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Wisdom
		resp, txn := db.Get(WisdomDB, wisdomID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		wisdom := &Wisdom{}
		err := json.Unmarshal(resp.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to delete this Wisdom
		_, canEdit := CheckWisdomAccess(user, wisdom, mainDB, db, r)
		if !canEdit {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &Wisdom{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		request.Type = strings.ToLower(request.Type)
		request.Type = strings.TrimSpace(request.Type)
		if request.Type != "lesson" &&
			request.Type != "reply" &&
			request.Type != "question" &&
			request.Type != "answer" &&
			request.Type != "box" &&
			request.Type != "task" &&
			request.Type != "post" &&
			request.Type != "course" &&
			request.Type != "proposal" {
			http.Error(w, "type must be one of lesson or reply or question or answer or box or task or post or course or proposal",
				http.StatusBadRequest)
			return
		}
		if request.Type == "task" || request.Type == "proposal" {
			if request.ReferenceUUID == "" {
				http.Error(w, "refID cannot be empty for tasks or proposals",
					http.StatusBadRequest)
				return
			}
		}
		// Check member and write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, request.KnowledgeUUID, mainDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Sanitize
		// request.Author = user.Username !!! oops! this was a mistake!
		request.Keywords = strings.ToLower(request.Keywords)
		if request.Collaborators == nil {
			request.Collaborators = make([]string, 0)
		}
		if request.Categories == nil {
			request.Categories = make([]Category, 0)
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(WisdomDB, txn, wisdomID, jsonEntry, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s;%s", request.KnowledgeUUID, request.Type),
			"refID-state":      fmt.Sprintf("%s;%t", request.ReferenceUUID, request.IsFinished),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		go db.NotifyTaskChange(user, request, wisdomID, mainDB, connector)
	}
}

func (db *GoDB) handleWisdomMove(mainDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Wisdom
		resp, txn := db.Get(WisdomDB, wisdomID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		wisdom := &Wisdom{}
		err := json.Unmarshal(resp.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to move this Wisdom
		_, canEdit := CheckWisdomAccess(user, wisdom, mainDB, db, r)
		if !canEdit {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &TaskMoveRequest{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check member and write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, wisdom.KnowledgeUUID, mainDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Check if we're just updating the row or if we also have to reconnect the task to another box
		if request.ToUUID != "" {
			// Check if new box exists and is actually of type box
			// Get Wisdom
			respBox, txnBox := db.Get(WisdomDB, request.ToUUID)
			if txnBox == nil {
				http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
				return
			}
			defer txnBox.Discard()
			newBox := &Wisdom{}
			err = json.Unmarshal(respBox.Data, newBox)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if newBox.Type != "box" {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			wisdom.ReferenceUUID = request.ToUUID
		}
		// Update row index temporarily
		wisdom.RowIndex = request.RowIndex
		db.rearrangeTasks(wisdom, wisdomID)
		// Store
		jsonEntry, err := json.Marshal(wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(WisdomDB, txn, wisdomID, jsonEntry, map[string]string{
			"refID-state": fmt.Sprintf("%s;%t", wisdom.ReferenceUUID, wisdom.IsFinished),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		go db.NotifyTaskChange(user, wisdom, wisdomID, mainDB, connector)
	}
}

func (db *GoDB) handleWisdomDelete(mainDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Wisdom
		resp, txn := db.Get(WisdomDB, wisdomID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		wisdom := &Wisdom{}
		err := json.Unmarshal(resp.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to delete this Wisdom
		_, canDelete := CheckWisdomAccess(user, wisdom, mainDB, db, r)
		if canDelete {
			// Is there an Analytics entry?
			if wisdom.AnalyticsUUID != "" {
				go func() {
					_ = db.Delete(AnaDB, wisdom.AnalyticsUUID, []string{})
				}()
			}
			txn.Discard()
			err = db.Delete(WisdomDB, wisdomID, []string{"knowledgeID-type", "refID-state"})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Create a notification for the author and all collaborators
			go func() {
				NotifyWisdomCollaborators(
					"Wisdom Deleted",
					fmt.Sprintf("%s deleted %s", user.DisplayName, wisdom.Name),
					user,
					wisdom,
					resp.uUID,
					db,
					connector)
				go db.NotifyTaskChange(user, wisdom, wisdomID, mainDB, connector)
			}()
		} else {
			txn.Discard()
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
}

func (db *GoDB) handleWisdomFinish(mainDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get task
		resp, txn := db.Get(WisdomDB, wisdomID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		wisdom := &Wisdom{}
		err := json.Unmarshal(resp.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to finish this task
		_, canFinish := CheckWisdomAccess(user, wisdom, mainDB, db, r)
		if canFinish {
			// Set meta data
			wisdom.IsFinished = !wisdom.IsFinished
			if wisdom.IsFinished {
				wisdom.TimeFinished = TimeNowIsoString()
			}
			// Update entry
			jsonEntry, err := json.Marshal(wisdom)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(WisdomDB, txn, wisdomID, jsonEntry, map[string]string{
				"refID-state": fmt.Sprintf("%s;%t", wisdom.ReferenceUUID, wisdom.IsFinished),
			})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Create a notification for the author and all collaborators
			go func() {
				NotifyWisdomCollaborators(
					"Task Finished",
					fmt.Sprintf("%s finished %s", user.DisplayName, wisdom.Name),
					user,
					wisdom,
					resp.uUID,
					db,
					connector)
				go db.NotifyTaskChange(user, wisdom, wisdomID, mainDB, connector)
			}()
		} else {
			txn.Discard()
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
}

func (db *GoDB) handleWisdomReaction(mainDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &ChatMessageReaction{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Sanitize
		request.Reaction = strings.ToLower(request.Reaction)
		// Retrieve wisdom and check if there is an Analytics entry available
		wisdomBytes, txnWis := db.Get(WisdomDB, wisdomID)
		if txnWis == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txnWis.Discard()
		wisdom := &Wisdom{}
		err := json.Unmarshal(wisdomBytes.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to react
		// If Wisdom is not public, check member and read right
		canRead, _ := CheckWisdomAccess(user, wisdom, mainDB, db, r)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		analyticsUpdate := false
		var analytics *Analytics
		var analyticsBytes *EntryResponse
		var txn *badger.Txn
		if wisdom.AnalyticsUUID != "" {
			analyticsBytes, txn = db.Get(AnaDB, wisdom.AnalyticsUUID)
			if txn != nil {
				defer txn.Discard()
				analytics = &Analytics{}
				err = json.Unmarshal(analyticsBytes.Data, analytics)
				if err != nil {
					// Could not retrieve analytics -> Create new one
					analytics = nil
				} else {
					analyticsUpdate = true
				}
			}
		}
		// Create analytics if there are none
		reactionRemoved := false
		if analytics == nil {
			analytics = &Analytics{
				Views:     0,
				Reactions: make([]Reaction, 1),
				Downloads: 0,
				Bookmarks: 0,
			}
			// analytics.Reactions[editMessage.Reaction] = []string{user.Username}
			analytics.Reactions[0] = Reaction{
				Type:      request.Reaction,
				Usernames: []string{user.Username},
			}
		} else {
			// Check if reaction is present already, if yes -> remove (toggle functionality)
			indexReaction := -1
			indexUser := -1
			for i, r := range analytics.Reactions {
				if r.Type == request.Reaction {
					indexReaction = i
					// Find user
					for ix, rUser := range r.Usernames {
						if rUser == user.Username {
							// Found -> Remove
							indexUser = ix
							break
						}
					}
					break
				}
			}
			if indexReaction != -1 {
				reactions := analytics.Reactions[indexReaction]
				if indexUser != -1 {
					// Delete
					reactions.Usernames = append(reactions.Usernames[:indexUser], reactions.Usernames[indexUser+1:]...)
					reactionRemoved = true
				} else {
					// Append
					reactions.Usernames = append(reactions.Usernames, user.Username)
				}
				analytics.Reactions[indexReaction] = reactions
			} else {
				// No reaction of this type existed yet
				// analytics.Reactions[editMessage.Reaction] = []string{user.Username}
				analytics.Reactions = append(analytics.Reactions, Reaction{
					Type:      request.Reaction,
					Usernames: []string{user.Username},
				})
			}
		}
		// Save
		analyticsJson, err := json.Marshal(analytics)
		if err != nil {
			return
		}
		// Commit changes
		if analyticsUpdate && analyticsBytes != nil {
			txnWis.Discard() // Discard wisdom transaction since we're not updating it in this branch anymore
			// Analytics existed -> Update them
			err = db.Update(AnaDB, txn, analyticsBytes.uUID, analyticsJson, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			// Insert analytics while returning its UUID to the wisdom for reference
			wisdom.AnalyticsUUID, err = db.Insert(AnaDB, analyticsJson, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Update wisdom
			wisdomJson, err := json.Marshal(wisdom)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(WisdomDB, txnWis, wisdomBytes.uUID, wisdomJson, nil)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		if reactionRemoved {
			return
		}
		// Create a notification for the author and all collaborators
		go func() {
			NotifyWisdomCollaborators(
				"Wisdom Reaction",
				fmt.Sprintf("%s reacted to %s", user.DisplayName, wisdom.Name),
				user,
				wisdom,
				wisdomBytes.uUID,
				db,
				connector)
		}()
	}
}

func NotifyWisdomCollaborators(title, message string, user *User, wisdom *Wisdom, wisdomID string,
	rapidDB *GoDB, connector *Connector,
) {
	usersToNotify := make([]string, len(wisdom.Collaborators)+1)
	skip := 0
	// Notify author if he is not the calling user
	if wisdom.Author != user.Username {
		usersToNotify[0] = wisdom.Author
		skip += 1
	}
	for i, collab := range wisdom.Collaborators {
		usersToNotify[i+skip] = collab
	}
	connector.SessionsMu.RLock()
	defer connector.SessionsMu.RUnlock()
	for _, collab := range usersToNotify {
		notification := &Notification{
			Title:             title,
			Description:       message,
			Type:              "info",
			TimeCreated:       TimeNowIsoString(),
			RecipientUsername: collab,
			ClickAction:       "open",
			ClickModule:       "wisdom",
			ClickUUID:         fmt.Sprintf("%s", wisdomID),
		}
		jsonNotification, err := json.Marshal(notification)
		if err != nil {
			continue
		}
		notificationUUID, err := rapidDB.Insert(NotifyDB, jsonNotification, map[string]string{
			"usr": FIndex(collab),
		})
		if err != nil {
			continue
		}
		// Now send a message via the connector
		session, ok := connector.Sessions.Get(collab)
		if !ok {
			continue
		}
		cMSG := &ConnectorMsg{
			Type:          "[s:NOTIFICATION]",
			Action:        "info",
			ReferenceUUID: notificationUUID,
			Username:      user.DisplayName,
			Message:       message,
		}
		_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	}
}

func (db *GoDB) NotifyTaskChange(
	user *User, wisdom *Wisdom, wisdomID string,
	mainDB *GoDB,
	connector *Connector,
) {
	// Retrieve users
	knowledgeBytes, ok := mainDB.Read(KnowledgeDB, wisdom.KnowledgeUUID)
	if !ok {
		return
	}
	knowledge := &Knowledge{}
	err := json.Unmarshal(knowledgeBytes.Data, knowledge)
	if err != nil {
		return
	}
	query := FIndex(knowledge.ChatGroupUUID)
	resp, err := mainDB.Select(MemberDB,
		map[string]string{
			"chat-usr": query,
		}, nil,
	)
	if err != nil {
		return
	}
	responseMember := <-resp
	if len(responseMember) < 1 {
		return
	}
	usersToNotify := make([]string, len(responseMember))
	for i, entry := range responseMember {
		chatMember := &ChatMember{}
		err = json.Unmarshal(entry.Data, chatMember)
		if err == nil {
			usersToNotify[i] = chatMember.Username
		}
	}
	// Notify users
	connector.SessionsMu.RLock()
	defer connector.SessionsMu.RUnlock()
	cMSG := &ConnectorMsg{
		Type:          "[s:CHANGE>TASK]",
		Action:        "reload",
		ReferenceUUID: wisdomID,
		Username:      user.DisplayName,
		Message:       "",
	}
	for _, collab := range usersToNotify {
		// Now send a message via the connector
		session, ok := connector.Sessions.Get(collab)
		if !ok {
			continue
		}
		_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	}
}

func (db *GoDB) NotifyMembersCustomMessage(
	title, message string, user *User, wisdom *Wisdom, wisdomID string,
	mainDB *GoDB,
	connector *Connector,
) {
	// Retrieve users
	knowledgeBytes, ok := mainDB.Read(KnowledgeDB, wisdom.KnowledgeUUID)
	if !ok {
		return
	}
	knowledge := &Knowledge{}
	err := json.Unmarshal(knowledgeBytes.Data, knowledge)
	if err != nil {
		return
	}
	query := FIndex(knowledge.ChatGroupUUID)
	resp, err := mainDB.Select(MemberDB,
		map[string]string{
			"chat-usr": query,
		}, nil,
	)
	if err != nil {
		return
	}
	responseMember := <-resp
	if len(responseMember) < 1 {
		return
	}
	usersToNotify := make([]string, len(responseMember))
	for i, entry := range responseMember {
		chatMember := &ChatMember{}
		err = json.Unmarshal(entry.Data, chatMember)
		if err == nil {
			if chatMember.Username == user.Username {
				continue
			}
			usersToNotify[i] = chatMember.Username
		}
	}
	// Notify users
	connector.SessionsMu.RLock()
	defer connector.SessionsMu.RUnlock()
	for _, collab := range usersToNotify {
		notification := &Notification{
			Title:             title,
			Description:       message,
			Type:              "info",
			TimeCreated:       TimeNowIsoString(),
			RecipientUsername: collab,
			ClickAction:       "open",
			ClickModule:       "wisdom",
			ClickUUID:         fmt.Sprintf("%s", wisdomID),
		}
		jsonNotification, err := json.Marshal(notification)
		if err != nil {
			continue
		}
		notificationUUID, err := db.Insert(NotifyDB, jsonNotification, map[string]string{
			"usr": FIndex(collab),
		})
		if err != nil {
			continue
		}
		// Now send a message via the connector
		session, ok := connector.Sessions.Get(collab)
		if !ok {
			continue
		}
		cMSG := &ConnectorMsg{
			Type:          "[s:NOTIFICATION]",
			Action:        "info",
			ReferenceUUID: notificationUUID,
			Username:      user.DisplayName,
			Message:       message,
		}
		_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	}
}

func CheckWisdomAccess(
	user *User, wisdom *Wisdom, mainDB, rapidDB *GoDB, r *http.Request,
) (canRead, canWrite bool) {
	// Check if write access is possible
	canWrite = false
	if wisdom.Author == user.Username {
		canWrite = true
	} else {
		for _, collaborator := range wisdom.Collaborators {
			if collaborator == user.Username {
				canWrite = true
				break
			}
		}
	}
	// Public wisdom does not require checking
	if wisdom.IsPublic {
		return true, canWrite
	}
	knowledgeBytes, okKnowledge := mainDB.Read(KnowledgeDB, wisdom.KnowledgeUUID)
	if !okKnowledge {
		return false, false
	}
	knowledge := &Knowledge{}
	err := json.Unmarshal(knowledgeBytes.Data, knowledge)
	if err != nil {
		return false, false
	}
	// Check if user has read rights for the specified chat group
	_, chatMember, chatGroup, err := ReadChatGroupAndMember(
		mainDB, rapidDB, nil,
		knowledge.ChatGroupUUID, user.Username, "", r)
	if err != nil {
		return false, false
	}
	canRead = CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
	return canRead, canWrite
}

func CheckKnowledgeAccess(
	user *User, knowledgeID string, mainDB *GoDB, r *http.Request,
) (canRead bool, canWrite bool) {
	knowledgeBytes, okKnowledge := mainDB.Read(KnowledgeDB, knowledgeID)
	if !okKnowledge {
		return false, false
	}
	knowledge := &Knowledge{}
	err := json.Unmarshal(knowledgeBytes.Data, knowledge)
	if err != nil {
		return false, false
	}
	// Check if user has read rights for the specified chat group
	_, chatMember, chatGroup, err := ReadChatGroupAndMember(
		mainDB, nil, nil,
		knowledge.ChatGroupUUID, user.Username, "", r)
	if err != nil {
		return false, false
	}
	canRead = CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
	canWrite = CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
	return canRead, canWrite
}

func (db *GoDB) handleWisdomReply(
	mainDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &Wisdom{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.ReferenceUUID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		request.Type = strings.ToLower(request.Type)
		if request.Type != "reply" && request.Type != "answer" {
			http.Error(w, "type must be one of reply or answer", http.StatusBadRequest)
			return
		}
		// Check member and write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, request.KnowledgeUUID, mainDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Does the referenced Wisdom exist?
		respRef, okRef := db.Read(WisdomDB, request.ReferenceUUID)
		if !okRef {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Does the referenced Wisdom belong to the same Knowledge?
		wisdomRef := &Wisdom{}
		err := json.Unmarshal(respRef.Data, wisdomRef)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if wisdomRef.KnowledgeUUID != request.KnowledgeUUID {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Sanitize
		request.Author = user.Username
		request.TimeCreated = TimeNowIsoString()
		request.Keywords = strings.ToLower(request.Keywords)
		// Add referenced Wisdom's keywords
		request.Keywords += "," + wisdomRef.Keywords
		if request.Collaborators == nil {
			request.Collaborators = make([]string, 0)
		}
		if request.Categories == nil {
			request.Categories = make([]Category, 0)
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(WisdomDB, jsonEntry, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s;%s", request.KnowledgeUUID, request.Type),
			"refID-state":      fmt.Sprintf("%s;%t", request.ReferenceUUID, request.IsFinished),
		})
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
		// Create a notification for the author and all collaborators
		NotifyWisdomCollaborators(
			"Wisdom Reply",
			fmt.Sprintf("%s replied to %s", user.DisplayName, wisdomRef.Name),
			user,
			wisdomRef,
			respRef.uUID,
			db,
			connector)
	}
}

func (db *GoDB) handleWisdomGetTasks(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		knowledgeID := chi.URLParam(r, "knowledgeID")
		if knowledgeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		knowledgeEntry, okKnowledge := mainDB.Read(KnowledgeDB, knowledgeID)
		if !okKnowledge {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		knowledge := &Knowledge{}
		err := json.Unmarshal(knowledgeEntry.Data, knowledge)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check member and write right
		knowledgeAccess, _ := CheckKnowledgeAccess(
			user, knowledgeEntry.uUID, mainDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Now retrieve all boxes (Wisdom with type box)
		// Boxes contain tasks which we will retrieve afterward
		resp, err := db.Select(WisdomDB, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s;box", knowledgeEntry.uUID),
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		boxes := &BoxesContainer{Boxes: make([]*BoxContainer, 0)}
		if len(response) < 1 {
			render.JSON(w, r, boxes)
			return
		}
		var box *Wisdom
		var analytics *Analytics
		for _, entry := range response {
			box = &Wisdom{}
			err = json.Unmarshal(entry.Data, box)
			if err != nil {
				continue
			}
			// Load analytics if available
			analytics = &Analytics{}
			if box.AnalyticsUUID != "" {
				anaBytes, okAna := db.Read(AnaDB, box.AnalyticsUUID)
				if !okAna {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						analytics = &Analytics{}
					}
				}
			}
			// Append box to boxes
			boxes.Boxes = append(boxes.Boxes, &BoxContainer{
				Box: &WisdomContainer{
					UUID:      entry.uUID,
					Wisdom:    box,
					Analytics: analytics,
				},
				Tasks: make([]*WisdomContainer, 0),
			})
		}
		// Are we selecting with a predefined status?
		stateFilter := r.URL.Query().Get("state")
		if stateFilter == "done" {
			stateFilter = ";true"
		} else if stateFilter == "todo" {
			stateFilter = ";false"
		} else {
			stateFilter = ""
		}
		// For each box get all tasks (Wisdom with type task) TODO: Make asynchronous
		var task *Wisdom
		var replies []*WisdomContainer
		var hasMoreReplies bool
		for bi, boxCon := range boxes.Boxes {
			respTask, err := db.Select(WisdomDB, map[string]string{
				"refID-state": boxCon.Box.UUID + stateFilter,
			}, nil)
			if err != nil {
				continue
			}
			responseTask := <-respTask
			if len(responseTask) < 1 {
				continue
			}
			for _, taskEntry := range responseTask {
				task = &Wisdom{}
				err = json.Unmarshal(taskEntry.Data, task)
				if err != nil {
					continue
				}
				// Load analytics if available
				analytics = &Analytics{}
				if task.AnalyticsUUID != "" {
					anaBytes, okAna := db.Read(AnaDB, task.AnalyticsUUID)
					if !okAna {
						err = json.Unmarshal(anaBytes.Data, analytics)
						if err != nil {
							analytics = &Analytics{}
						}
					}
				}
				// Get recent replies
				replies, hasMoreReplies = db.RetrieveWisdomReplies(task, taskEntry.uUID, 3)
				// Append to results
				boxes.Boxes[bi].Tasks = append(boxes.Boxes[bi].Tasks, &WisdomContainer{
					UUID:           taskEntry.uUID,
					Wisdom:         task,
					Analytics:      analytics,
					Replies:        replies,
					HasMoreReplies: hasMoreReplies,
				})
			}
			sort.SliceStable(
				boxes.Boxes[bi].Tasks, func(i, j int) bool {
					return boxes.Boxes[bi].Tasks[i].RowIndex < boxes.Boxes[bi].Tasks[j].RowIndex
				},
			)
		}
		// Return to client
		render.JSON(w, r, boxes)
	}
}

func (db *GoDB) handleWisdomQuery(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		timeStart := time.Now()
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		knowledgeID := chi.URLParam(r, "knowledgeID")
		if knowledgeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		canRead, _ := CheckKnowledgeAccess(user, knowledgeID, mainDB, r)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &WisdomQuery{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Retrieve all Wisdom entries of specified type (if provided)
		if request.Type == ".*" || request.Type == "." {
			request.Type = ""
		}
		// Options?
		options := r.Context().Value("pagination").(*SelectOptions)
		if request.MaxResults > 0 {
			options.MaxResults = int64(request.MaxResults)
		}
		if options.MaxResults <= 0 {
			options.MaxResults = -1
		}
		queryResponse := &QueryResponse{
			TimeSeconds: 0,
			Lessons:     make([]*WisdomContainer, 0),
			Replies:     make([]*WisdomContainer, 0),
			Questions:   make([]*WisdomContainer, 0),
			Answers:     make([]*WisdomContainer, 0),
			Boxes:       make([]*WisdomContainer, 0),
			Tasks:       make([]*WisdomContainer, 0),
			Posts:       make([]*WisdomContainer, 0),
			Courses:     make([]*WisdomContainer, 0),
			Misc:        make([]*WisdomContainer, 0),
		}
		// Turn query text into a full regex pattern
		words, p := GetRegexQuery(request.Query)
		var replies []*WisdomContainer
		var hasMoreReplies bool
		var container *WisdomContainer
		var wisdom *Wisdom
		var analytics *Analytics
		var points int64
		var accuracy float64
		b := false
		response, _, err := db.SSelect(WisdomDB, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s;%s", knowledgeID, request.Type),
		}, options, 10, int(options.MaxResults))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		for entry := range response {
			wisdom = &Wisdom{}
			err = json.Unmarshal(entry.Data, wisdom)
			if err != nil {
				continue
			}
			// Check state of wisdom and skip if needed
			if request.State != "" && request.State != "any" {
				if request.State == "true" || request.State == "done" {
					if !wisdom.IsFinished {
						continue
					}
				} else if request.State == "false" || request.State == "todo" {
					if wisdom.IsFinished {
						continue
					}
				}
			}
			// Check if wisdom fits the search criteria
			if request.Query == "." || request.Query == ".*" {
				accuracy = 1
				points = 1
			} else {
				// Flip boolean on each iteration
				b = !b
				accuracy, points = GetWisdomQueryPoints(wisdom, request, p, words, b)
			}
			if points <= 0.0 {
				continue
			}
			// Truncate wisdom description
			if wisdom.Description != "" {
				if request.MaxDescriptionLength > 0 {
					wisdom.Description = EllipticalTruncate(wisdom.Description, request.MaxDescriptionLength)
				} else {
					wisdom.Description = EllipticalTruncate(wisdom.Description, 200)
				}
			}
			// Load analytics if available
			analytics = &Analytics{}
			if wisdom.AnalyticsUUID != "" {
				anaBytes, okAna := db.Read(AnaDB, wisdom.AnalyticsUUID)
				if okAna {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						analytics = &Analytics{}
					}
				}
			}
			// Do we need to retrieve replies for this wisdom?
			if request.WithReplies {
				replies, hasMoreReplies = db.RetrieveWisdomReplies(wisdom, entry.uUID, 3)
			} else {
				replies = make([]*WisdomContainer, 0)
				hasMoreReplies = false
			}
			container = &WisdomContainer{
				UUID:           entry.uUID,
				Wisdom:         wisdom,
				Analytics:      analytics,
				Accuracy:       accuracy,
				Replies:        replies,
				HasMoreReplies: hasMoreReplies,
			}
			switch wisdom.Type {
			case "lesson":
				queryResponse.Lessons = append(queryResponse.Lessons, container)
			case "reply":
				queryResponse.Replies = append(queryResponse.Replies, container)
			case "question":
				queryResponse.Questions = append(queryResponse.Questions, container)
			case "answer":
				queryResponse.Answers = append(queryResponse.Answers, container)
			case "box":
				queryResponse.Boxes = append(queryResponse.Boxes, container)
			case "task":
				queryResponse.Tasks = append(queryResponse.Tasks, container)
			case "post":
				queryResponse.Posts = append(queryResponse.Posts, container)
			case "course":
				queryResponse.Courses = append(queryResponse.Courses, container)
			default:
				queryResponse.Misc = append(queryResponse.Misc, container)
			}
		}
		// Do we need to sort?
		if !request.NoSort {
			// Sort entries by accuracy
			if len(queryResponse.Lessons) > 1 {
				sort.SliceStable(
					queryResponse.Lessons, func(i, j int) bool {
						return queryResponse.Lessons[i].Accuracy > queryResponse.Lessons[j].Accuracy
					},
				)
			}
			if len(queryResponse.Replies) > 1 {
				sort.SliceStable(
					queryResponse.Replies, func(i, j int) bool {
						return queryResponse.Replies[i].Accuracy > queryResponse.Replies[j].Accuracy
					},
				)
			}
			if len(queryResponse.Questions) > 1 {
				sort.SliceStable(
					queryResponse.Questions, func(i, j int) bool {
						return queryResponse.Questions[i].Accuracy > queryResponse.Questions[j].Accuracy
					},
				)
			}
			if len(queryResponse.Answers) > 1 {
				sort.SliceStable(
					queryResponse.Answers, func(i, j int) bool {
						return queryResponse.Answers[i].Accuracy > queryResponse.Answers[j].Accuracy
					},
				)
			}
			if len(queryResponse.Boxes) > 1 {
				sort.SliceStable(
					queryResponse.Boxes, func(i, j int) bool {
						return queryResponse.Boxes[i].Accuracy > queryResponse.Boxes[j].Accuracy
					},
				)
			}
			if len(queryResponse.Tasks) > 1 {
				sort.SliceStable(
					queryResponse.Tasks, func(i, j int) bool {
						return queryResponse.Tasks[i].Accuracy > queryResponse.Tasks[j].Accuracy
					},
				)
			}
			if len(queryResponse.Misc) > 1 {
				sort.SliceStable(
					queryResponse.Misc, func(i, j int) bool {
						return queryResponse.Misc[i].Accuracy > queryResponse.Misc[j].Accuracy
					},
				)
			}
		}
		duration := time.Since(timeStart)
		queryResponse.TimeSeconds = duration.Seconds()
		render.JSON(w, r, queryResponse)
	}
}

func GetWisdomQueryPoints(
	wisdom *Wisdom, query *WisdomQuery, p *regexp.Regexp, words map[string]*QueryWord, b bool,
) (float64, int64) {
	// Get all matches in selected fields
	var mUser, mName, mDesc, mKeys, mCats []string
	if query.Fields == "" || strings.Contains(query.Fields, "usr") {
		mUser = p.FindAllString(wisdom.Author, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "title") {
		mName = p.FindAllString(wisdom.Name, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "desc") {
		mDesc = p.FindAllString(wisdom.Description, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "keys") {
		mKeys = p.FindAllString(wisdom.Keywords, -1)
	}
	if (query.Fields == "" || strings.Contains(query.Fields, "cats")) && len(wisdom.Categories) > 0 {
		tmp := ""
		for i := 0; i < len(wisdom.Categories); i++ {
			tmp += wisdom.Categories[i].Name + " "
		}
		mCats = p.FindAllString(tmp, -1)
	}
	if len(mUser) < 1 && len(mName) < 1 && len(mDesc) < 1 && len(mKeys) < 1 && len(mCats) < 1 {
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
	// How many words were matched?
	for _, word := range words {
		if word.B == b {
			points += word.Points
		}
	}
	accuracy = float64(points) / float64(pointsMax)
	return accuracy, points
}

func (db *GoDB) handleGetContributors(mainDB *GoDB,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		knowledgeID := chi.URLParam(r, "knowledgeID")
		if knowledgeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		knowledgeEntry, okKnowledge := mainDB.Read(KnowledgeDB, knowledgeID)
		if !okKnowledge {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		knowledge := &Knowledge{}
		err := json.Unmarshal(knowledgeEntry.Data, knowledge)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check member and read right
		knowledgeAccess, _ := CheckKnowledgeAccess(
			user, knowledgeEntry.uUID, mainDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Now retrieve all wisdom entries and count contributors (authors in this case)
		resp, err := db.Select(WisdomDB, map[string]string{
			"knowledgeID-type": knowledgeEntry.uUID,
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		contributors := TopContributors{Contributors: make([]*ContributorStat, 0)}
		if len(response) < 1 {
			render.JSON(w, r, contributors)
			return
		}
		conMap := map[string]*ContributorStat{}
		var box *Wisdom
		for _, entry := range response {
			box = &Wisdom{}
			err = json.Unmarshal(entry.Data, box)
			if err != nil {
				continue
			}
			if conMap[box.Author] == nil {
				conMap[box.Author] = &ContributorStat{
					Username:    box.Author,
					WisdomCount: 1,
				}
			} else {
				conMap[box.Author].WisdomCount += 1
			}
		}
		// Write back...
		for _, stat := range conMap {
			contributors.Contributors = append(contributors.Contributors, stat)
		}
		// ...and sort it
		sort.SliceStable(
			contributors.Contributors, func(i, j int) bool {
				return contributors.Contributors[i].WisdomCount > contributors.Contributors[j].WisdomCount
			},
		)
		// Respond
		render.JSON(w, r, contributors)
	}
}

func (db *GoDB) rearrangeTasks(wisdom *Wisdom, uUID string) {
	// Rearrange all tasks inside this box
	var position int
	if wisdom.RowIndex <= 0.0 {
		// Index below 0 -> Attach to the end
		position = 1
	} else if wisdom.RowIndex < 1.0 {
		// Index between 0 and 1 -> Put in front but redistribute new index values starting from 20_000
		position = -1
	} else {
		// Index greater than 1 -> Put it where it belongs
		// We still redistribute row indices if the distance becomes too small
		position = 0
	}
	respTask, err := db.Select(WisdomDB, map[string]string{
		"refID-state": fmt.Sprintf("%s;false", wisdom.ReferenceUUID),
	}, nil)
	if err == nil {
		responseTask := <-respTask
		if len(responseTask) > 0 {
			if position == 1 {
				// Attach task to the end of all other tasks
				highestRow := 0.0
				for _, taskEntry := range responseTask {
					// Do not check task being edited here since we already did that
					if taskEntry.uUID == uUID {
						continue
					}
					task := &Wisdom{}
					err = json.Unmarshal(taskEntry.Data, task)
					if err != nil {
						continue
					}
					if task.RowIndex > highestRow {
						highestRow = task.RowIndex
					}
				}
				wisdom.RowIndex = highestRow + 20_000.0
			} else if position == -1 {
				// Put in front and redistribute all others following
				wisdom.RowIndex = 20_000.0
				v := 40_000.0
				for _, taskEntry := range responseTask {
					task := &Wisdom{}
					err = json.Unmarshal(taskEntry.Data, task)
					if err != nil {
						continue
					}
					task.RowIndex = v
					// Increment
					v += 20_000.0
					// Update
					jsonEntry, err := json.Marshal(task)
					if err != nil {
						continue
					}
					_, txSeg := db.Get(WisdomDB, taskEntry.uUID)
					if txSeg == nil {
						continue
					}
					_ = db.Update(WisdomDB, txSeg, taskEntry.uUID, jsonEntry, map[string]string{
						"refID-state": fmt.Sprintf("%s;%t", wisdom.ReferenceUUID, wisdom.IsFinished),
					})
				}
			}
		}
	}
}

func (db *GoDB) handleWisdomInvestigate(mainDB *GoDB,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Read(WisdomDB, wisdomID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		wisdom := &Wisdom{}
		err := json.Unmarshal(response.Data, wisdom)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// If Wisdom is not public, check member and read right
		canRead, _ := CheckWisdomAccess(
			user, wisdom, mainDB, db, r)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		resp, _, err := db.SSelect(WisdomDB, map[string]string{
			"refID-state": wisdomID,
		}, nil, 10, 0)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		queryResponse := &QueryResponse{
			TimeSeconds: 0,
			Lessons:     make([]*WisdomContainer, 0),
			Replies:     make([]*WisdomContainer, 0),
			Questions:   make([]*WisdomContainer, 0),
			Answers:     make([]*WisdomContainer, 0),
			Boxes:       make([]*WisdomContainer, 0),
			Tasks:       make([]*WisdomContainer, 0),
			Posts:       make([]*WisdomContainer, 0),
			Courses:     make([]*WisdomContainer, 0),
			Proposals:   make([]*WisdomContainer, 0),
			Misc:        make([]*WisdomContainer, 0),
		}
		var analytics *Analytics
		if wisdom.ReferenceUUID != "" {
			responseReference, ok := db.Read(WisdomDB, wisdom.ReferenceUUID)
			if ok {
				wisdomRef := &Wisdom{}
				err := json.Unmarshal(responseReference.Data, wisdomRef)
				if err == nil {
					// Load analytics if available
					if wisdomRef.AnalyticsUUID != "" {
						anaBytes, ok := db.Read(AnaDB, wisdomRef.AnalyticsUUID)
						if ok {
							analytics = &Analytics{}
							err = json.Unmarshal(anaBytes.Data, analytics)
							if err != nil {
								analytics = &Analytics{}
							}
						}
					}
					queryResponse.ReferenceWisdom = &WisdomContainer{
						UUID:      responseReference.uUID,
						Wisdom:    wisdomRef,
						Analytics: analytics,
						Accuracy:  0,
					}
				}
			}
		}
		// responseRef := <-resp
		// if len(responseRef) < 1 {
		//   render.JSON(w, r, queryResponse)
		//   return
		// }
		var container *WisdomContainer
		for entry := range resp {
			wisdom = &Wisdom{}
			err = json.Unmarshal(entry.Data, wisdom)
			if err != nil {
				continue
			}
			// Load analytics if available
			analytics = &Analytics{}
			if wisdom.AnalyticsUUID != "" {
				anaBytes, okAna := db.Read(AnaDB, wisdom.AnalyticsUUID)
				if okAna {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						analytics = &Analytics{}
					}
				}
			}
			container = &WisdomContainer{
				UUID:      entry.uUID,
				Wisdom:    wisdom,
				Analytics: analytics,
			}
			switch wisdom.Type {
			case "lesson":
				queryResponse.Lessons = append(queryResponse.Lessons, container)
			case "reply":
				queryResponse.Replies = append(queryResponse.Replies, container)
			case "question":
				queryResponse.Questions = append(queryResponse.Questions, container)
			case "answer":
				queryResponse.Answers = append(queryResponse.Answers, container)
			case "box":
				queryResponse.Boxes = append(queryResponse.Boxes, container)
			case "task":
				queryResponse.Tasks = append(queryResponse.Tasks, container)
			case "post":
				queryResponse.Posts = append(queryResponse.Posts, container)
			case "course":
				queryResponse.Courses = append(queryResponse.Courses, container)
			case "proposal":
				queryResponse.Proposals = append(queryResponse.Proposals, container)
			default:
				queryResponse.Misc = append(queryResponse.Misc, container)
			}
		}
		render.JSON(w, r, queryResponse)
	}
}

func (db *GoDB) handleWisdomModification(mainDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Wisdom
		resp, txn := db.Get(WisdomDB, wisdomID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		wisdom := &Wisdom{}
		err := json.Unmarshal(resp.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to delete this Wisdom
		_, canEdit := CheckWisdomAccess(user, wisdom, mainDB, db, r)
		if !canEdit {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &WisdomModification{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Type == "edit" {
			if request.Field == "due" {
				wisdom.TimeDue = request.NewValue
			} else if request.Field == "dueEnd" {
				wisdom.TimeDueEnd = request.NewValue
			} else if request.Field == "title" {
				wisdom.Name = request.NewValue
			} else if request.Field == "desc" {
				wisdom.Description = request.NewValue
			} else if request.Field == "chapters" {
				wisdom = db.handleWisdomChaptersEdit(wisdom, request)
			}
			// Store
			jsonEntry, err := json.Marshal(wisdom)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(WisdomDB, txn, wisdomID, jsonEntry, map[string]string{
				"knowledgeID-type": fmt.Sprintf("%s;%s", wisdom.KnowledgeUUID, wisdom.Type),
				"refID-state":      fmt.Sprintf("%s;%t", wisdom.ReferenceUUID, wisdom.IsFinished),
			})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			go db.NotifyTaskChange(user, wisdom, wisdomID, mainDB, connector)
		}
	}
}

func (db *GoDB) handleWisdomChaptersEdit(wisdom *Wisdom, request *WisdomModification) *Wisdom {
	highestIndex := -1
	// Check if chapter uuid is present if there are chapters
	ix := -1
	if len(wisdom.Chapters) > 0 {
		uidCheck := request.NewValue
		for i, chapter := range wisdom.Chapters {
			if chapter.Index > highestIndex {
				highestIndex = chapter.Index
			}
			if chapter.UUID == uidCheck {
				ix = i
			}
		}
	}
	if ix != -1 {
		// Remove chapter
		wisdom.Chapters = append(wisdom.Chapters[:ix], wisdom.Chapters[ix+1:]...)
		// Reassign chapter indices to ensure order
		if len(wisdom.Chapters) > 0 {
			ix = 0
			for _, chapter := range wisdom.Chapters {
				chapter.Index = ix
				ix += 1
			}
		}
	} else {
		// Add chapter
		chapterIndex := highestIndex + 1
		// Retrieve targeted wisdom entry (the chapter to be added)
		resp, txn := db.Get(WisdomDB, request.NewValue)
		if txn == nil {
			return wisdom
		}
		defer txn.Discard()
		chapterWisdom := &Wisdom{}
		err := json.Unmarshal(resp.Data, chapterWisdom)
		if err != nil {
			return wisdom
		}
		// Store new chapter
		newChapter := WisdomChapter{
			UUID:        request.NewValue,
			Name:        chapterWisdom.Name,
			Author:      chapterWisdom.Author,
			Keywords:    chapterWisdom.Keywords,
			Categories:  chapterWisdom.Categories,
			TimeCreated: chapterWisdom.TimeCreated,
			Index:       chapterIndex,
		}
		wisdom.Chapters = append(wisdom.Chapters, newChapter)
	}
	return wisdom
}

func (db *GoDB) handleWisdomAcceptAnswer(mainDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get reply or proposal
		resp, ok := db.Read(WisdomDB, wisdomID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		wisdom := &Wisdom{}
		err := json.Unmarshal(resp.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if wisdom.ReferenceUUID == "" || (wisdom.Type != "reply" && wisdom.Type != "proposal") {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get referenced entry
		respQ, txnQ := db.Get(WisdomDB, wisdom.ReferenceUUID)
		if txnQ == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txnQ.Discard()
		wisdomQ := &Wisdom{}
		err = json.Unmarshal(respQ.Data, wisdomQ)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Replies need a question as a parent, proposals just need some parent
		if wisdom.Type == "reply" && wisdomQ.Type != "question" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Check if user has right to accept answers for this question
		// In case or a proposal, we check if user can accept proposals for the parent entry
		_, canFinish := CheckWisdomAccess(user, wisdomQ, mainDB, db, r)
		if !canFinish {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		if wisdom.Type == "reply" {
			// Mark answer as actual answer by switching its type from reply to answer
			wisdom.Type = "answer"
			// Mark question as answered by switching its state and setting current date as finished date
			wisdomQ.IsFinished = true
			wisdomQ.TimeFinished = TimeNowIsoString()
			// Commit changes by first attempting to update the question itself
			jsonEntry, err := json.Marshal(wisdomQ)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(WisdomDB, txnQ, wisdom.ReferenceUUID, jsonEntry, map[string]string{
				"knowledgeID-type": fmt.Sprintf("%s;%s", wisdomQ.KnowledgeUUID, wisdomQ.Type),
				"refID-state":      fmt.Sprintf("%s;%t", wisdomQ.ReferenceUUID, wisdomQ.IsFinished),
			})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			// We will not modify the referenced entry
			txnQ.Discard()
			if wisdom.Type == "proposal" {
				// Mark proposal as done
				wisdom.IsFinished = true
				wisdom.TimeFinished = TimeNowIsoString()
			}
		}
		// ...now save the accepted entry
		_, txn := db.Get(WisdomDB, wisdomID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Store
		jsonEntry, err := json.Marshal(wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(WisdomDB, txn, wisdomID, jsonEntry, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s;%s", wisdom.KnowledgeUUID, wisdom.Type),
			"refID-state":      fmt.Sprintf("%s;%t", wisdom.ReferenceUUID, wisdom.IsFinished),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Notify question collaborators
		var title string
		var desc string
		if wisdom.Type == "reply" || wisdom.Type == "answer" {
			title = "Question Answered"
			desc = fmt.Sprintf("Question %s answered", wisdomQ.Name)
		} else if wisdom.Type == "proposal" {
			title = "New Accepted Proposal"
			desc = fmt.Sprintf("%s received an accepted proposal", wisdomQ.Name)
		}
		go func() {
			NotifyWisdomCollaborators(
				title,
				desc,
				user,
				wisdomQ,
				respQ.uUID,
				db,
				connector)
			go db.NotifyTaskChange(user, wisdomQ, respQ.uUID, mainDB, connector)
		}()
		// Notify answerer
		if wisdom.Type == "reply" || wisdom.Type == "answer" {
			title = "Answer Accepted"
			desc = fmt.Sprintf("Your answer for %s got accepted", wisdomQ.Name)
		} else if wisdom.Type == "proposal" {
			title = "Proposal Accepted"
			desc = fmt.Sprintf("Your proposal for %s got accepted", wisdomQ.Name)
		}
		go func() {
			NotifyWisdomCollaborators(
				title,
				desc,
				user,
				wisdom,
				resp.uUID,
				db,
				connector)
			go db.NotifyTaskChange(user, wisdom, wisdomID, mainDB, connector)
		}()
	}
}

func (db *GoDB) handleWisdomMetaRetrieval(mainDB *GoDB,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		knowledgeID := chi.URLParam(r, "knowledgeID")
		if knowledgeID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		queryType := r.URL.Query().Get("type")
		if queryType == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		queryType = strings.ToLower(queryType)
		knowledgeEntry, okKnowledge := mainDB.Read(KnowledgeDB, knowledgeID)
		if !okKnowledge {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		knowledge := &Knowledge{}
		err := json.Unmarshal(knowledgeEntry.Data, knowledge)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check member and read right
		knowledgeAccess, _ := CheckKnowledgeAccess(
			user, knowledgeEntry.uUID, mainDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// What are we trying to retrieve?
		if queryType == "keys" {
			db.retrieveWisdomKeys(w, r, knowledgeID)
		}
	}
}

func (db *GoDB) retrieveWisdomKeys(w http.ResponseWriter, r *http.Request, knowledgeID string) {
	resp, err := db.Select(WisdomDB, map[string]string{
		"knowledgeID-type": FIndex(knowledgeID),
	}, &SelectOptions{
		MaxResults: 1_000,
		Page:       0,
		Skip:       0,
	})
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	keys := WisdomKeywordList{Keywords: make([]string, 0)}
	response := <-resp
	if len(response) < 1 {
		render.JSON(w, r, keys)
		return
	}
	var wisdom *Wisdom
	var keyList []string
	for _, result := range response {
		wisdom = &Wisdom{}
		err = json.Unmarshal(result.Data, wisdom)
		if wisdom.Keywords == "" {
			continue
		}
		// Split keywords and attach them to the list
		keyList = strings.Split(wisdom.Keywords, ",")
		if len(keyList) < 1 {
			continue
		}
		for _, key := range keyList {
			keys.Keywords = append(keys.Keywords, key)
		}
	}
	render.JSON(w, r, keys)
}

func (db *GoDB) handleWisdomReminderRequest(mainDB *GoDB,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Wisdom
		resp, ok := db.Read(WisdomDB, wisdomID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		wisdom := &Wisdom{}
		err := json.Unmarshal(resp.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to delete this Wisdom
		canRead, _ := CheckWisdomAccess(user, wisdom, mainDB, db, r)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &WisdomReminderRequest{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.TriggerDateTime == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Parse trigger date time
		triggerTime, err := IsoStringToTime(request.TriggerDateTime)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Do we need to delay the action?
		if request.TriggerDelay != "" {
			delayDuration, err := time.ParseDuration(request.TriggerDelay)
			if err == nil {
				triggerTime = triggerTime.Add(delayDuration)
			}
		}
		// Convert date to UTC date to avoid weird timezone problems
		triggerTime = triggerTime.UTC()
		// Write back to request
		request.TriggerDateTime = TimeToIsoString(triggerTime)
		// Create periodic action
		action := &PeriodicAction{
			NotificationTemplate: Notification{
				Title:       request.Title,
				Description: request.Description,
				Type:        "reminder",
			},
			Username:            user.Username,
			Topic:               "",
			Recipients:          request.Recipients,
			ChatGroupID:         "",
			ChatGroupRole:       nil,
			TriggerDateTime:     request.TriggerDateTime,
			IsReoccurring:       request.IsReoccurring,
			ReoccurringInterval: request.ReoccurringInterval,
			ReoccurringAmount:   request.ReoccurringAmount,
			WebhookURLs:         make([]Webhook, 0),
		}
		// Generate unix timestamp for due date
		action.TriggerDateTimeUnix = triggerTime.Unix()
		// Store
		jsonEntry, err := json.Marshal(action)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, err = db.Insert(PeriodDB, jsonEntry, map[string]string{
			"usr": FIndex(user.Username),
			"due": action.TriggerDateTime,
			"ref": fmt.Sprintf("%s;%s", wisdom.Type, resp.uUID),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleWisdomExport(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		wisdomID := chi.URLParam(r, "wisdomID")
		if wisdomID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Read(WisdomDB, wisdomID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		wisdom := &Wisdom{}
		err := json.Unmarshal(response.Data, wisdom)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// If Wisdom is not public, check member and read right
		canRead, _ := CheckWisdomAccess(
			user, wisdom, mainDB, db, r)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Is this entry a lesson/question/reply/response/task? If so, we export it as is
		// If we have encountered a box, then we will export all tasks belonging to this box
		if wisdom.Type != "box" {
			// Export wisdom content as Markdown text
			textContent := strings.Builder{}
			textContent.WriteString(fmt.Sprintf("%s\n\n", wisdom.Name))
			textContent.WriteString(wisdom.Description)
			// Respond to client
			_, _ = fmt.Fprintln(w, textContent.String())
			return
		}
		// Retrieve tasks and export those
		// Are we selecting with a predefined status?
		stateFilter := r.URL.Query().Get("state")
		if stateFilter == "done" {
			stateFilter = ";true"
		} else if stateFilter == "todo" {
			stateFilter = ";false"
		} else {
			stateFilter = ""
		}
		var task *Wisdom
		respTask, err := db.Select(WisdomDB, map[string]string{
			"refID-state": wisdomID + stateFilter,
		}, nil)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		responseTask := <-respTask
		if len(responseTask) < 1 {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		textContent := strings.Builder{}
		for _, taskEntry := range responseTask {
			task = &Wisdom{}
			err = json.Unmarshal(taskEntry.Data, task)
			if err != nil {
				continue
			}
			textContent.WriteString(fmt.Sprintf("%s\n", task.Name))
			textContent.WriteString(fmt.Sprintf("%s\n\n", task.Description))
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, textContent.String())
	}
}

func (db *GoDB) RetrieveWisdomReplies(
	wisdom *Wisdom, wisdomID string, maxAmount int,
) ([]*WisdomContainer, bool) {
	replies := make([]*WisdomContainer, 0)
	hasMoreReplies := false
	resp, err := db.Select(WisdomDB, map[string]string{
		"refID-state": wisdomID,
	}, nil)
	if err != nil {
		return replies, false
	}
	var analytics *Analytics
	responseRef := <-resp
	if len(responseRef) < 1 {
		return replies, false
	}
	var container *WisdomContainer
	for _, entry := range responseRef {
		wisdom = &Wisdom{}
		err = json.Unmarshal(entry.Data, wisdom)
		if err != nil {
			continue
		}
		if wisdom.Type != "reply" {
			continue
		}
		// Load analytics if available
		analytics = &Analytics{}
		if wisdom.AnalyticsUUID != "" {
			anaBytes, okAna := db.Read(AnaDB, wisdom.AnalyticsUUID)
			if okAna {
				err = json.Unmarshal(anaBytes.Data, analytics)
				if err != nil {
					analytics = &Analytics{}
				}
			}
		}
		container = &WisdomContainer{
			UUID:      entry.uUID,
			Wisdom:    wisdom,
			Analytics: analytics,
		}
		replies = append(replies, container)
		// Stop after reaching limit
		if len(replies) >= maxAmount {
			// Would there be more replies?
			if len(replies) < len(responseRef) {
				hasMoreReplies = true
			}
			return replies, hasMoreReplies
		}
	}
	return replies, hasMoreReplies
}
