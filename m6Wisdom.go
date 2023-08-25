package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
	"strings"
)

type Wisdom struct {
	Name          string   `json:"t"`
	Description   string   `json:"desc"`
	Keywords      string   `json:"keys"`
	Author        string   `json:"usr"`
	Type          string   `json:"type"`
	TimeCreated   string   `json:"ts"`
	KnowledgeUUID string   `json:"pid"`
	Categories    []string `json:"cats"`
	ReferenceUUID string   `json:"ref"` // References another Wisdom e.g. Comment referencing Answer
	AnalyticsUUID string   `json:"ana"` // Views, likes etc. will be stored in a separate database
	IsPublic      bool     `json:"pub"`
	Collaborators []string `json:"coll"`
}

func OpenWisdomDatabase() *GoDB {
	db := OpenDB("knowledge", []string{
		"knowledgeID-type", "refID",
	})
	return db
}

func (db *GoDB) ProtectedWisdomEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB, analyticsDB *GoDB, connector *Connector,
) {
	r.Route(
		"/wisdom/private", func(r chi.Router) {
			r.Post("/create", db.handleWisdomCreate(chatGroupDB, chatMemberDB, knowledgeDB, notificationDB, connector))
			r.Post("/react/{wisdomID}", db.handleWisdomReaction(
				chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB, notificationDB))
			r.Get("/get/{wisdomID}", db.handleWisdomGet(chatGroupDB, chatMemberDB, knowledgeDB))
			r.Get("/delete/{wisdomID}", db.handleWisdomDelete(chatGroupDB, chatMemberDB))
		},
	)
}

func (db *GoDB) handleWisdomGet(chatGroupDB, chatMemberDB, knowledgeDB *GoDB) http.HandlerFunc {
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
		response, lid := db.Get(wisdomID)
		if lid == "" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer db.Unlock(wisdomID, lid)
		wisdom := &Wisdom{}
		err := json.Unmarshal(response.Data, wisdom)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// If Wisdom is not public, check member and read right
		if !wisdom.IsPublic {
			knowledgeBytes, lidKnowledge := knowledgeDB.Get(wisdom.KnowledgeUUID)
			if lidKnowledge == "" {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			defer knowledgeDB.Unlock(wisdom.KnowledgeUUID, lidKnowledge)
			knowledge := &Knowledge{}
			err = json.Unmarshal(knowledgeBytes.Data, knowledge)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Check if user has read rights for the specified chat group
			_, chatMember, chatGroup, err := GetChatGroupAndMember(
				chatGroupDB, chatMemberDB, nil, nil,
				knowledge.ChatGroupUUID, user.Username, "", nil)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			canRead := CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
			if !canRead {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
		render.JSON(w, r, wisdom)
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
		// Check member and write right
		knowledgeBytes, lidKnowledge := knowledgeDB.Get(request.KnowledgeUUID)
		if lidKnowledge == "" {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer knowledgeDB.Unlock(request.KnowledgeUUID, lidKnowledge)
		knowledge := &Knowledge{}
		err := json.Unmarshal(knowledgeBytes.Data, knowledge)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has read rights for the specified chat group
		_, chatMember, chatGroup, err := GetChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			knowledge.ChatGroupUUID, user.Username, "", nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Sanitize
		request.Author = user.Username
		request.TimeCreated = TimeNowIsoString()
		request.Type = strings.ToLower(request.Type)
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
		uUID, err := db.Insert(jsonEntry, map[string]string{
			"knowledgeID-type": fmt.Sprintf("%s|%s", knowledgeBytes.uUID, request.Type),
			"refID":            request.ReferenceUUID,
		})
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleWisdomDelete(chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
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
		// Get message
		resp, lid := db.Get(wisdomID)
		if lid == "" {
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
		// User is allowed to delete if:
		// 		1. User is owner of Wisdom
		//		2. User is collaborator of Wisdom
		canDelete := false
		if wisdom.Author == user.Username {
			canDelete = true
		} else {
			for _, collaborator := range wisdom.Collaborators {
				if collaborator == user.Username {
					canDelete = true
					break
				}
			}
		}
		if canDelete {
			err := db.Delete(wisdomID)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			db.Unlock(wisdomID, lid)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
	}
}

func (db *GoDB) handleWisdomReaction(
	chatGroupDB, chatMemberDB, knowledgeDB, analyticsDB, notificationDB *GoDB) http.HandlerFunc {
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
		wisdomBytes, lid := db.Get(wisdomID)
		if lid == "" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		wisdom := &Wisdom{}
		err := json.Unmarshal(wisdomBytes.Data, wisdom)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to react
		// Check member and write right
		knowledgeBytes, lidKnowledge := knowledgeDB.Get(wisdom.KnowledgeUUID)
		if lidKnowledge == "" {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer knowledgeDB.Unlock(wisdom.KnowledgeUUID, lidKnowledge)
		knowledge := &Knowledge{}
		err = json.Unmarshal(knowledgeBytes.Data, knowledge)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has read rights for the specified chat group
		_, chatMember, chatGroup, err := GetChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			knowledge.ChatGroupUUID, user.Username, "", nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		var analytics *Analytics
		analyticsUpdate := false
		var analyticsBytes *EntryResponse
		if wisdom.AnalyticsUUID != "" {
			analyticsBytes, lid = analyticsDB.Get(wisdom.AnalyticsUUID)
			if lid == "" {
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
				} else {
					// Append
					reactions = append(reactions, user.Username)
				}
				analytics.Reactions[request.Reaction] = reactions
			}
		}
		analyticsJson, err := json.Marshal(analytics)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Commit changes
		if analyticsUpdate && analyticsBytes != nil {
			// Analytics existed -> Update them
			err = analyticsDB.Update(analyticsBytes.uUID, analyticsJson, map[string]string{})
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
			err = db.Update(wisdomBytes.uUID, wisdomJson, map[string]string{
				"knowledgeID-type": fmt.Sprintf("%s|%s", wisdom.KnowledgeUUID, wisdom.Type),
				"refID":            wisdom.ReferenceUUID,
			})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
	}
}
