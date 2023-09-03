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

type Wisdom struct {
	Name                 string   `json:"t"`
	Description          string   `json:"desc"`
	Keywords             string   `json:"keys"`
	Author               string   `json:"usr"`
	Type                 string   `json:"type"`
	TimeCreated          string   `json:"ts"`
	TimeFinished         string   `json:"tsd"`
	IsFinished           bool     `json:"done"`
	KnowledgeUUID        string   `json:"pid"`
	Categories           []string `json:"cats"`
	ReferenceUUID        string   `json:"ref"` // References another Wisdom e.g. Comment referencing Answer
	AnalyticsUUID        string   `json:"ana"` // Views, likes etc. will be stored in a separate database
	IsPublic             bool     `json:"pub"`
	Collaborators        []string `json:"coll"`
	ThumbnailURL         string   `json:"iurl"`
	ThumbnailAnimatedURL string   `json:"iurla"`
	BannerURL            string   `json:"burl"`
	BannerAnimatedURL    string   `json:"burla"`
}

type WisdomContainer struct {
	UUID string `json:"uid"`
	*Wisdom
	*Analytics
	Accuracy float64 `json:"accuracy"`
}

type BoxesContainer struct {
	Boxes []*BoxContainer
}

type BoxContainer struct {
	Box   *WisdomContainer   `json:"box"`
	Tasks []*WisdomContainer `json:"tasks"`
}

type QueryResponse struct {
	TimeSeconds float64            `json:"respTime"`
	Lessons     []*WisdomContainer `json:"lessons"`
	Replies     []*WisdomContainer `json:"replies"`
	Questions   []*WisdomContainer `json:"questions"`
	Answers     []*WisdomContainer `json:"answers"`
	Boxes       []*WisdomContainer `json:"boxes"`
	Tasks       []*WisdomContainer `json:"tasks"`
	Misc        []*WisdomContainer `json:"misc"`
}

type WisdomQuery struct {
	Query  string `json:"query"`
	Type   string `json:"type"`
	Fields string `json:"fields"`
}

type QueryWord struct {
	B      bool
	Points int64
}

func OpenWisdomDatabase() *GoDB {
	db := OpenDB("wisdom")
	return db
}

func (db *GoDB) ProtectedWisdomEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB, analyticsDB *GoDB, connector *Connector,
) {
	r.Route("/wisdom/private", func(r chi.Router) {
		r.Post("/create", db.handleWisdomCreate(
			chatGroupDB, chatMemberDB, knowledgeDB, notificationDB, connector))
		r.Post("/edit/{wisdomID}", db.handleWisdomEdit(
			chatGroupDB, chatMemberDB, knowledgeDB, connector))
		r.Post("/reply", db.handleWisdomReply(
			chatGroupDB, chatMemberDB, knowledgeDB, notificationDB, connector))
		r.Post("/react/{wisdomID}", db.handleWisdomReaction(
			chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB, notificationDB, connector))
		r.Post("/query/{knowledgeID}", db.handleWisdomQuery(
			chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB))
		r.Get("/get/{wisdomID}", db.handleWisdomGet(
			chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB))
		r.Get("/delete/{wisdomID}", db.handleWisdomDelete(
			chatGroupDB, chatMemberDB, knowledgeDB, notificationDB, analyticsDB, connector))
		r.Get("/finish/{wisdomID}", db.handleWisdomFinish(
			chatGroupDB, chatMemberDB, knowledgeDB, notificationDB, connector))
		r.Get("/tasks/{knowledgeID}", db.handleWisdomGetTasks(
			chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB))
	})
}

func (db *GoDB) handleWisdomGet(chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB *GoDB) http.HandlerFunc {
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
		response, ok := db.Read(wisdomID)
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
			user, wisdom, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Is there an analytics entry?
		analytics := &Analytics{}
		if wisdom.AnalyticsUUID != "" {
			anaBytes, txn := analyticsDB.Get(wisdom.AnalyticsUUID)
			if txn != nil {
				defer txn.Discard()
				err := json.Unmarshal(anaBytes.Data, analytics)
				if err != nil {
					analytics = &Analytics{}
				} else {
					analytics.Views += 1
					// Asynchronously update view count in database
					go func() {
						jsonAna, err := json.Marshal(analytics)
						if err == nil {
							_ = analyticsDB.Update(txn, wisdom.AnalyticsUUID, jsonAna, map[string]string{})
						}
					}()
				}
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
	if a.Name == "" {
		return errors.New("missing name")
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

func (db *GoDB) handleWisdomCreate(
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB *GoDB, connector *Connector,
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
			request.Type != "task" {
			http.Error(w, "type must be one of lesson or answer or box or task",
				http.StatusBadRequest)
			return
		}
		if request.Type == "task" {
			if request.ReferenceUUID == "" {
				http.Error(w, "refID cannot be empty for tasks",
					http.StatusBadRequest)
				return
			}
		}
		// Check member and write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, request.KnowledgeUUID, chatGroupDB, chatMemberDB, knowledgeDB, r)
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
			request.Categories = make([]string, 0)
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
		uUID, err := db.Insert(jsonEntry, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s\\|%s", request.KnowledgeUUID, request.Type),
			"refID":            request.ReferenceUUID,
		})
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
		go NotifyTaskChange(user, request, uUID, knowledgeDB, chatMemberDB, connector)
	}
}

func (db *GoDB) handleWisdomEdit(
	chatGroupDB, chatMemberDB, knowledgeDB *GoDB, connector *Connector,
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
		resp, txn := db.Get(wisdomID)
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
		_, canEdit := CheckWisdomAccess(user, wisdom, chatGroupDB, chatMemberDB, knowledgeDB, r)
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
			request.Type != "task" {
			http.Error(w, "type must be one of lesson or reply or answer or answer or box or task",
				http.StatusBadRequest)
			return
		}
		if request.Type == "task" {
			if request.ReferenceUUID == "" {
				http.Error(w, "refID cannot be empty for tasks",
					http.StatusBadRequest)
				return
			}
		}
		// Check member and write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, request.KnowledgeUUID, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Sanitize
		request.Author = user.Username
		request.Keywords = strings.ToLower(request.Keywords)
		if request.Collaborators == nil {
			request.Collaborators = make([]string, 0)
		}
		if request.Categories == nil {
			request.Categories = make([]string, 0)
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(txn, wisdomID, jsonEntry, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s\\|%s", request.KnowledgeUUID, request.Type),
			"refID":            request.ReferenceUUID,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		go NotifyTaskChange(user, request, wisdomID, knowledgeDB, chatMemberDB, connector)
	}
}

func (db *GoDB) handleWisdomDelete(
	chatGroupDB, chatMemberDB, knowledgeDB, notificationDB, analyticsDB *GoDB, connector *Connector,
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
		resp, txn := db.Get(wisdomID)
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
		_, canDelete := CheckWisdomAccess(user, wisdom, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if canDelete {
			// Is there an Analytics entry?
			if wisdom.AnalyticsUUID != "" {
				go func() {
					_ = analyticsDB.Delete(wisdom.AnalyticsUUID)
				}()
			}
			txn.Discard()
			err := db.Delete(wisdomID)
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
					notificationDB,
					connector)
				go NotifyTaskChange(user, wisdom, wisdomID, knowledgeDB, chatMemberDB, connector)
			}()
		} else {
			txn.Discard()
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
}

func (db *GoDB) handleWisdomFinish(
	chatGroupDB, chatMemberDB, knowledgeDB, notificationDB *GoDB, connector *Connector,
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
		resp, txn := db.Get(wisdomID)
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
		_, canFinish := CheckWisdomAccess(user, wisdom, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if canFinish {
			// Set meta data
			wisdom.TimeFinished = TimeNowIsoString()
			wisdom.IsFinished = true
			// Update entry
			jsonEntry, err := json.Marshal(wisdom)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(txn, wisdomID, jsonEntry, map[string]string{
				"knowledgeID-type": fmt.Sprintf("%s\\|%s", wisdom.KnowledgeUUID, wisdom.Type),
				"refID":            wisdom.ReferenceUUID,
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
					notificationDB,
					connector)
				go NotifyTaskChange(user, wisdom, wisdomID, knowledgeDB, chatMemberDB, connector)
			}()
		} else {
			txn.Discard()
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
}

func (db *GoDB) handleWisdomReaction(
	chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB, notificationDB *GoDB, connector *Connector,
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
		wisdomBytes, txnWis := db.Get(wisdomID)
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
		canRead, _ := CheckWisdomAccess(user, wisdom, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		analyticsUpdate := false
		var analytics *Analytics
		var analyticsBytes *EntryResponse
		var txn *badger.Txn
		if wisdom.AnalyticsUUID != "" {
			analyticsBytes, txn = analyticsDB.Get(wisdom.AnalyticsUUID)
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
				Reactions: make(map[string][]string, 1),
				Downloads: 0,
				Bookmarks: 0,
			}
			analytics.Reactions[request.Reaction] = []string{user.Username}
		} else {
			// Check if reaction is present already, if yes -> remove (toggle functionality)
			index := -1
			rUsers, ok := analytics.Reactions[request.Reaction]
			if ok && len(rUsers) > 0 {
				for ix, rUser := range rUsers {
					if rUser == user.Username {
						// Found -> Remove
						index = ix
						break
					}
				}
				reactions := analytics.Reactions[request.Reaction]
				if index != -1 {
					// Delete
					reactions = append(reactions[:index], reactions[index+1:]...)
					reactionRemoved = true
				} else {
					// Append
					reactions = append(reactions, user.Username)
				}
				analytics.Reactions[request.Reaction] = reactions
			} else {
				// No reaction of this type existed yet
				analytics.Reactions[request.Reaction] = []string{user.Username}
			}
		}
		analyticsJson, err := json.Marshal(analytics)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Commit changes
		if analyticsUpdate && analyticsBytes != nil {
			txnWis.Discard()
			// Analytics existed -> Update them
			err = analyticsDB.Update(txn, analyticsBytes.uUID, analyticsJson, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			// Insert analytics while returning its UUID to the wisdom for reference
			wisdom.AnalyticsUUID, err = analyticsDB.Insert(analyticsJson, map[string]string{})
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
			err = db.Update(txnWis, wisdomBytes.uUID, wisdomJson, map[string]string{
				"knowledgeID-type": fmt.Sprintf("%s\\|%s", wisdom.KnowledgeUUID, wisdom.Type),
				"refID":            wisdom.ReferenceUUID,
			})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		if reactionRemoved {
			return
		}
		// Create a notification for the author and all collaborators
		NotifyWisdomCollaborators(
			"Wisdom Reaction",
			fmt.Sprintf("%s reacted to %s", user.DisplayName, wisdom.Name),
			user,
			wisdom,
			wisdomBytes.uUID,
			notificationDB,
			connector)
	}
}

func NotifyWisdomCollaborators(title, message string, user *User, wisdom *Wisdom, wisdomID string,
	notificationDB *GoDB, connector *Connector,
) {
	usersToNotify := make([]string, len(wisdom.Collaborators)+1)
	usersToNotify[0] = wisdom.Author
	for i, collab := range wisdom.Collaborators {
		usersToNotify[i+1] = collab
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
		notificationUUID, err := notificationDB.Insert(jsonNotification, map[string]string{
			"usr": collab,
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

func NotifyTaskChange(
	user *User, wisdom *Wisdom, wisdomID string,
	knowledgeDB, chatMemberDB *GoDB,
	connector *Connector,
) {
	// Retrieve users
	knowledgeBytes, ok := knowledgeDB.Read(wisdom.KnowledgeUUID)
	if !ok {
		return
	}
	knowledge := &Knowledge{}
	err := json.Unmarshal(knowledgeBytes.Data, knowledge)
	if err != nil {
		return
	}
	query := fmt.Sprintf("%s\\|", knowledge.ChatGroupUUID)
	resp, err := chatMemberDB.Select(
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

func CheckWisdomAccess(
	user *User, wisdom *Wisdom, chatGroupDB, chatMemberDB, knowledgeDB *GoDB, r *http.Request,
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
	knowledgeBytes, okKnowledge := knowledgeDB.Read(wisdom.KnowledgeUUID)
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
		chatGroupDB, chatMemberDB, nil, nil,
		knowledge.ChatGroupUUID, user.Username, "", r)
	if err != nil {
		return false, false
	}
	canRead = CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
	return canRead, canWrite
}

func CheckKnowledgeAccess(
	user *User, knowledgeID string, chatGroupDB, chatMemberDB, knowledgeDB *GoDB, r *http.Request,
) (canRead bool, canWrite bool) {
	knowledgeBytes, okKnowledge := knowledgeDB.Read(knowledgeID)
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
		chatGroupDB, chatMemberDB, nil, nil,
		knowledge.ChatGroupUUID, user.Username, "", r)
	if err != nil {
		return false, false
	}
	canRead = CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
	canWrite = CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
	return canRead, canWrite
}

func (db *GoDB) handleWisdomReply(
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB *GoDB, connector *Connector,
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
			user, request.KnowledgeUUID, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Does the referenced Wisdom exist?
		respRef, okRef := db.Read(request.ReferenceUUID)
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
			request.Categories = make([]string, 0)
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(jsonEntry, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s\\|%s", request.KnowledgeUUID, request.Type),
			"refID":            request.ReferenceUUID,
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
			notificationDB,
			connector)
	}
}

func (db *GoDB) handleWisdomGetTasks(
	chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB *GoDB,
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
		knowledgeEntry, okKnowledge := knowledgeDB.Read(knowledgeID)
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
			user, knowledgeEntry.uUID, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Now retrieve all boxes (Wisdom with type box)
		// Boxes contain tasks which we will retrieve afterwards
		resp, err := db.Select(map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s\\|box\\|", knowledgeEntry.uUID),
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
				anaBytes, okAna := analyticsDB.Read(box.AnalyticsUUID)
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
		// For each box get all tasks (Wisdom with type task) TODO: Make asynchronous
		var task *Wisdom
		var taskQuery string
		for bi, boxCon := range boxes.Boxes {
			taskQuery = fmt.Sprintf("%s", boxCon.Box.UUID)
			respTask, err := db.Select(map[string]string{
				"refID": taskQuery,
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
					anaBytes, okAna := analyticsDB.Read(task.AnalyticsUUID)
					if !okAna {
						err = json.Unmarshal(anaBytes.Data, analytics)
						if err != nil {
							analytics = &Analytics{}
						}
					}
				}
				boxes.Boxes[bi].Tasks = append(boxes.Boxes[bi].Tasks, &WisdomContainer{
					UUID:      taskEntry.uUID,
					Wisdom:    task,
					Analytics: analytics,
				})
			}
		}
		// Return to client
		render.JSON(w, r, boxes)
	}
}

func (db *GoDB) handleWisdomQuery(
	chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB *GoDB,
) http.HandlerFunc {
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
		canRead, _ := CheckKnowledgeAccess(user, knowledgeID, chatGroupDB, chatMemberDB, knowledgeDB, r)
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
		// Retrieve all Wisdom entries
		typeQuery := request.Type
		if typeQuery == "" || typeQuery == ".*" {
			typeQuery = ".+"
		}
		ixQuery := fmt.Sprintf("%s\\|%s\\|", knowledgeID, typeQuery)
		resp, err := db.Select(map[string]string{
			"knowledgeID-type": ixQuery,
		}, nil)
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
			Misc:        make([]*WisdomContainer, 0),
		}
		response := <-resp
		if len(response) < 1 {
			render.JSON(w, r, queryResponse)
			return
		}
		// Turn query text into a full regex pattern
		words, p := GetRegexQuery(request.Query)
		var container *WisdomContainer
		var wisdom *Wisdom
		var analytics *Analytics
		var points int64
		var accuracy float64
		b := false
		for _, entry := range response {
			wisdom = &Wisdom{}
			err = json.Unmarshal(entry.Data, wisdom)
			if err != nil {
				continue
			}
			// Flip boolean on each iteration
			b = !b
			accuracy, points = GetWisdomQueryPoints(wisdom, request, p, words, b)
			if points <= 0.0 {
				continue
			}
			// Load analytics if available
			analytics = &Analytics{}
			if wisdom.AnalyticsUUID != "" {
				anaBytes, okAna := analyticsDB.Read(wisdom.AnalyticsUUID)
				if !okAna {
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
				Accuracy:  accuracy,
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
			default:
				queryResponse.Misc = append(queryResponse.Misc, container)
			}
		}
		duration := time.Since(timeStart)
		queryResponse.TimeSeconds = duration.Seconds()
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
		render.JSON(w, r, queryResponse)
	}
}

func GetWisdomQueryPoints(
	wisdom *Wisdom, query *WisdomQuery, p *regexp.Regexp, words map[string]*QueryWord, b bool,
) (float64, int64) {
	// Get all matches in selected fields
	var mUser, mName, mDesc, mKeys []string
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
	if len(mUser) < 1 && len(mName) < 1 && len(mDesc) < 1 && len(mKeys) < 1 {
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
		words[strings.ToLower(word)].B = b
	}
	for _, word := range mName {
		words[strings.ToLower(word)].B = b
	}
	for _, word := range mDesc {
		words[strings.ToLower(word)].B = b
	}
	for _, word := range mKeys {
		words[strings.ToLower(word)].B = b
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

// GetRegexQuery converts a string of words into a regex pattern
// Example:
//
//	Query "ice cream cones" would turn into...
//		((ice)(\s?cream)?(\s?cones)?|(cream)(\s?cones)?|(cones))
//	Thus creating a list of words as following...
//		ice cream cones icecream creamcones icecreamcones
func GetRegexQuery(query string) (map[string]*QueryWord, *regexp.Regexp) {
	// Remove leading and trailing spaces
	clean := strings.TrimSpace(query)
	if clean == "" {
		return map[string]*QueryWord{}, nil
	}
	// Replace duplicate spaces with singular spaces
	spaces := regexp.MustCompile("\\s+")
	clean = spaces.ReplaceAllString(clean, " ")
	// Split query into words
	words := strings.Split(clean, " ")
	wordCount := len(words)
	builder := &strings.Builder{}
	// Case-insensitive
	builder.WriteString("(?i)")
	// Attach all words
	wordMap := map[string]*QueryWord{}
	var queryWord *QueryWord
	for i, word := range words {
		wordMap[word] = &QueryWord{
			B:      false,
			Points: 1,
		}
		if i > 0 {
			// Add alternation if we're on the second iteration and onwards
			builder.WriteString("|")
		}
		// Single word
		builder.WriteString("(")
		builder.WriteString(word)
		builder.WriteString(")")
		// Neighboring words
		if i < wordCount-1 && wordCount > 1 {
			queryWord = &QueryWord{
				B:      false,
				Points: 2, // 1 + Group Bonus = 2
			}
			// Attach neighbor to ensure context is being captured better
			wordMap[fmt.Sprintf("%s%s", words[i], words[i+1])] = queryWord
			wordMap[fmt.Sprintf("%s-%s", words[i], words[i+1])] = queryWord
			wordMap[fmt.Sprintf("%s-%s", words[i], words[i+1])] = queryWord
			builder.WriteString("((\\s|-)?")
			builder.WriteString(words[i+1])
			builder.WriteString(")?")
		}
	}
	return wordMap, regexp.MustCompile(builder.String())
}
