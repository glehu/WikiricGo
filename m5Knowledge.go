package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
)

type Category struct {
	Name     string `json:"t"`
	ColorHex string `json:"hex"`
}

type Knowledge struct {
	Name          string     `json:"t"`
	Description   string     `json:"desc"`
	TimeCreated   string     `json:"ts"`
	ChatGroupUUID string     `json:"pid"`
	Categories    []Category `json:"cats"`
}

func OpenKnowledgeDatabase() *GoDB {
	db := OpenDB("knowledge")
	return db
}

func (db *GoDB) ProtectedKnowledgeEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth, chatGroupDB, chatMemberDB *GoDB, chatServer *ChatServer,
) {
	r.Route("/knowledge/private", func(r chi.Router) {
		r.Post("/create", db.handleKnowledgeCreate(chatGroupDB, chatMemberDB, chatServer))
		r.Post("/cats/mod/{knowledgeID}", db.handleKnowledgeCategoryModification())
		r.Get("/get/{knowledgeID}", db.handleKnowledgeGet(chatGroupDB, chatMemberDB))
		r.Get("/chat/{chatID}", db.handleKnowledgeGetFromChatID(chatGroupDB, chatMemberDB))
	})
}

func (a *Knowledge) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	if a.ChatGroupUUID == "" {
		return errors.New("missing chatID")
	}
	return nil
}

func (a *Category) Bind(_ *http.Request) error {
	if a.Name == "" {
		return errors.New("missing name")
	}
	return nil
}

func (db *GoDB) handleKnowledgeCreate(chatGroupDB, chatMemberDB *GoDB, chatServer *ChatServer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &Knowledge{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check if user has admin rights for the specified chat group
		_, chatMember, chatGroup, err := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			request.ChatGroupUUID, user.Username, "", r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		userRole := chatMember.GetRoleInformation(chatGroup.ChatGroup)
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !userRole.IsAdmin || !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Sanitize
		request.TimeCreated = TimeNowIsoString()
		if request.Categories == nil {
			request.Categories = make([]Category, 0)
		}
		// Create new knowledge now
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(jsonEntry, map[string]string{
			"chatID": request.ChatGroupUUID,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) handleKnowledgeGet(chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
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
		response, ok := db.Read(knowledgeID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		knowledge := &Knowledge{}
		err := json.Unmarshal(response.Data, knowledge)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has read rights for the specified chat group
		_, chatMember, chatGroup, err := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			knowledge.ChatGroupUUID, user.Username, "", r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canRead := CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		render.JSON(w, r, knowledge)
	}
}

func (db *GoDB) handleKnowledgeGetFromChatID(chatGroupDB, chatMemberDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		chatID := chi.URLParam(r, "knowledgeID")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		query := fmt.Sprintf("%s\\|", chatID)
		resp, err := db.Select(map[string]string{
			"chatID": query,
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
		knowledge := &Knowledge{}
		err = json.Unmarshal(response[0].Data, knowledge)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has read rights for the specified chat group
		_, chatMember, chatGroup, err := ReadChatGroupAndMember(
			chatGroupDB, chatMemberDB, nil, nil,
			knowledge.ChatGroupUUID, user.Username, "", r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canRead := CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		render.JSON(w, r, knowledge)
	}
}

func (db *GoDB) handleKnowledgeCategoryModification() http.HandlerFunc {
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
		// Retrieve chat group
		response, txn := db.Get(knowledgeID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		knowledge := &Knowledge{}
		err := json.Unmarshal(response.Data, knowledge)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if role is present
		index := -1
		for ix, role := range knowledge.Categories {
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
			knowledge.Categories = append(knowledge.Categories[:index], knowledge.Categories[index+1:]...)
		} else {
			// Did it exist yet?
			if index == -1 {
				knowledge.Categories = append(knowledge.Categories, *request)
			} else {
				knowledge.Categories[index] = *request
			}
		}
		jsonEntry, err := json.Marshal(knowledge)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(txn, response.uUID, jsonEntry, map[string]string{
			"chatID": knowledge.ChatGroupUUID,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}
