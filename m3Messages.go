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
	"sort"
	"strings"
)

const MessageDB = "m3"

type ChatMessage struct {
	ChatGroupUUID string `json:"pid"`
	Text          string `json:"msg"`
	Username      string `json:"usr"`
	TimeCreated   string `json:"ts"`
	WasEdited     bool   `json:"e"`
	AnalyticsUUID string `json:"ana"` // Views, likes etc. will be stored in a separate database
}

type ChatMessageReaction struct {
	Reaction string `json:"reaction"`
}

type ChatMessageContainer struct {
	*ChatMessage
	*Analytics
	UUID string `json:"uid"`
}

type ChatMessagesResponse struct {
	Messages []*ChatMessageContainer `json:"messages"`
}

type ChatActionMessage struct {
	*ChatMessageContainer
	Action string `json:"action"`
}

type MessageDistribution struct {
	*ChatGroupEntry `json:"channel"`
	Count           int64                 `json:"count"`
	Reactions       int64                 `json:"reacts"`
	Contributors    []*MessageContributor `json:"contributors"`
}

type MessageContributor struct {
	Username  string `json:"usr"`
	Count     int64  `json:"count"`
	Reactions int64  `json:"reacts"`
}

func (db *GoDB) ProtectedChatMessagesEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth, chatServer *ChatServer, mainDB *GoDB,
) {
	r.Route("/msg/private", func(r chi.Router) {
		r.Post("/create", db.handleChatMessageCreate(chatServer, mainDB))
		r.Post("/edit/{msgID}", db.handleChatMessageEdit(chatServer, mainDB))
		r.Post("/react/{msgID}", db.handleChatMessageReaction(chatServer, mainDB))
		r.Get("/delete/{msgID}", db.handleChatMessageDelete(chatServer, mainDB))
		// Chat Related Route
		r.Route("/chat", func(r chi.Router) {
			r.Get("/get/{chatID}", db.handleChatMessageFromChat(chatServer, mainDB))
		})
	})
}

func (db *GoDB) handleChatMessageCreate(chatServer *ChatServer, mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &ChatMessage{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		chatGroup, chatMember, _, _ := ReadChatGroupAndMember(
			mainDB, db, nil,
			request.ChatGroupUUID, user.Username, password, r)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Initialize message
		request.TimeCreated = TimeNowIsoString()
		request.Username = user.Username
		request.WasEdited = false
		// Store message
		jsonMessage, err := json.Marshal(request)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(MessageDB,
			jsonMessage, map[string]string{
				"chatID": request.ChatGroupUUID,
			},
		)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
		// Distribute message
		go chatServer.DistributeChatMessageJSON(&ChatMessageContainer{
			ChatMessage: request,
			UUID:        uUID,
		})
	}
}

func (db *GoDB) handleChatMessageEdit(chatServer *ChatServer, mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		msgID := chi.URLParam(r, "msgID")
		if msgID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve POST payload
		request := &ChatMessage{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		chatGroup, chatMember, _, _ := ReadChatGroupAndMember(
			mainDB, db, nil,
			request.ChatGroupUUID, user.Username, password, r)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Get message
		_, txn := db.Get(MessageDB, msgID)
		defer txn.Discard()
		// Initialize message
		request.TimeCreated = TimeNowIsoString()
		request.Username = user.Username
		request.WasEdited = true // Edited!
		// Distribute action message
		actionMessage := &ChatActionMessage{
			ChatMessageContainer: &ChatMessageContainer{
				ChatMessage: request,
				UUID:        msgID,
			},
			Action: "edit",
		}
		go chatServer.DistributeChatActionMessageJSON(actionMessage)
		// Store message
		jsonMessage, err := json.Marshal(request)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(MessageDB, txn, msgID, jsonMessage, map[string]string{
			"chatID": request.ChatGroupUUID,
		})
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, msgID)
	}
}

func (a *ChatMessage) Bind(_ *http.Request) error {
	if a.Text == "" {
		return errors.New("missing text")
	}
	if a.ChatGroupUUID == "" {
		return errors.New("missing parent")
	}
	return nil
}

func (a *ChatMessageReaction) Bind(_ *http.Request) error {
	if a.Reaction == "" {
		return errors.New("missing reaction")
	}
	return nil
}

func (db *GoDB) handleChatMessageFromChat(
	chatServer *ChatServer, mainDB *GoDB,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		chatID := chi.URLParam(r, "chatID")
		if chatID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		chatGroup, chatMember, _, err := ReadChatGroupAndMember(
			mainDB, db, nil,
			chatID, user.Username, password, r)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if chatGroup == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		// Check rights
		canRead := CheckReadRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canRead {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Options?
		options := r.Context().Value("pagination").(*SelectOptions)
		if options.MaxResults <= 0 {
			options.MaxResults = 50
		}
		// Retrieve messages from this chat group
		resp, err := db.Select(MessageDB, map[string]string{
			"chatID": chatID,
		}, options)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		response := <-resp
		messages := ChatMessagesResponse{Messages: make([]*ChatMessageContainer, len(response))}
		if len(response) < 1 {
			render.JSON(w, r, messages)
			return
		}
		for i, result := range response {
			msg := &ChatMessage{}
			err = json.Unmarshal(result.Data, msg)
			if err == nil {
				analytics := &Analytics{}
				if msg.AnalyticsUUID != "" {
					anaBytes, ok := db.Read(AnaDB, msg.AnalyticsUUID)
					if ok {
						err = json.Unmarshal(anaBytes.Data, analytics)
						if err != nil {
							analytics = &Analytics{}
						}
					}
				}
				container := &ChatMessageContainer{
					ChatMessage: msg,
					Analytics:   analytics,
					UUID:        result.uUID,
				}
				messages.Messages[i] = container
			}
		}
		render.JSON(w, r, messages)
	}
}

func (db *GoDB) handleChatMessageDelete(chatServer *ChatServer, mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		msgID := chi.URLParam(r, "msgID")
		if msgID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get message
		resp, txn := db.Get(MessageDB, msgID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		message := &ChatMessage{}
		err := json.Unmarshal(resp.Data, message)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		_, chatMember, chatGroup, _ := ReadChatGroupAndMember(
			mainDB, db, nil,
			message.ChatGroupUUID, user.Username, password, r)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Is the user the author of this message?
		if message.Username != user.Username {
			// No... does the user have admin rights?
			usrRole := chatMember.GetRoleInformation(chatGroup.ChatGroup)
			if !usrRole.IsAdmin {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
		// Distribute action message (including sanitized chat message)
		message.Username = ""
		message.Text = ""
		message.TimeCreated = ""
		container := &ChatMessageContainer{
			ChatMessage: message,
			UUID:        resp.uUID,
		}
		actionMessage := &ChatActionMessage{
			ChatMessageContainer: container,
			Action:               "delete",
		}
		go chatServer.DistributeChatActionMessageJSON(actionMessage)
		// Delete message
		txn.Discard()
		err = db.Delete(MessageDB, msgID, []string{"chatID"})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleChatMessageReaction(
	chatServer *ChatServer, mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		msgID := chi.URLParam(r, "msgID")
		if msgID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		chatID := r.URL.Query().Get("src")
		if chatID == "" {
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
		// Check if a password was provided in the url query
		password := r.URL.Query().Get("pw")
		// Check rights of group member
		chatGroup, chatMember, _, _ := ReadChatGroupAndMember(
			mainDB, db, nil, chatID, user.Username, password, r)
		if chatMember == nil {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		canWrite := CheckWriteRights(chatMember.ChatMember, chatGroup.ChatGroup)
		if !canWrite {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve message and check if there is an Analytics entry available
		messageBytes, txnMsg := db.Get(MessageDB, msgID)
		if txnMsg == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txnMsg.Discard()
		message := &ChatMessage{}
		err := json.Unmarshal(messageBytes.Data, message)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		analyticsUpdate := false
		var analytics *Analytics
		var analyticsBytes *EntryResponse
		var txn *badger.Txn
		if message.AnalyticsUUID != "" {
			analyticsBytes, txn = db.Get(AnaDB, message.AnalyticsUUID)
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
			// analytics.Reactions[request.Reaction] = []string{s.ChatMember.Username}
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
				// analytics.Reactions[request.Reaction] = []string{user.Username}
				analytics.Reactions = append(analytics.Reactions, Reaction{
					Type:      request.Reaction,
					Usernames: []string{user.Username},
				})
			}
		}
		// Distribute action message
		actionMsg := &ChatMessage{}
		actionMsg.Username = user.Username // User that reacted
		actionMsg.Text = request.Reaction  // Reaction as msg
		actionMsg.TimeCreated = ""
		actionMsg.WasEdited = reactionRemoved // Edit=true if reaction existed before thus was removed
		actionMsg.ChatGroupUUID = message.ChatGroupUUID
		container := &ChatMessageContainer{
			ChatMessage: actionMsg,
			UUID:        messageBytes.uUID,
		}
		actionMessage := &ChatActionMessage{
			ChatMessageContainer: container,
			Action:               "react",
		}
		go chatServer.DistributeChatActionMessageJSON(actionMessage)
		// Save
		analyticsJson, err := json.Marshal(analytics)
		if err != nil {
			return
		}
		// Commit changes
		if analyticsUpdate && analyticsBytes != nil {
			// Analytics existed -> Update them
			err = db.Update(AnaDB, txn, analyticsBytes.uUID, analyticsJson, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else {
			// Insert analytics while returning its UUID to the message for reference
			message.AnalyticsUUID, err = db.Insert(AnaDB, analyticsJson, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			// Update message
			messageJson, err := json.Marshal(message)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(MessageDB, txnMsg, messageBytes.uUID, messageJson, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
	}
}

func (db *GoDB) GetChatMessageDistribution(chatMember *ChatMember, mainDB *GoDB, chatID string) *MessageDistribution {
	chatGroup, err := mainDB.ReadChatGroup(chatID)
	if err != nil {
		return nil
	}
	canRead := CheckWriteRights(chatMember, chatGroup.ChatGroup)
	if !canRead {
		return nil
	}
	// Retrieve messages from this chat group
	resp, err := db.Select(MessageDB, map[string]string{
		"chatID": chatID,
	}, nil)
	if err != nil {
		return nil
	}
	response := <-resp
	if len(response) < 1 {
		return nil
	}
	dist := &MessageDistribution{
		ChatGroupEntry: chatGroup,
		Count:          0,
		Contributors:   make([]*MessageContributor, 0),
	}
	contributors := map[string]int64{}
	reactors := map[string]int64{}
	for _, result := range response {
		msg := &ChatMessage{}
		err = json.Unmarshal(result.Data, msg)
		if err != nil {
			continue
		}
		// Retrieve analytics
		analytics := &Analytics{}
		if msg.AnalyticsUUID != "" {
			anaBytes, ok := db.Read(AnaDB, msg.AnalyticsUUID)
			if ok {
				err = json.Unmarshal(anaBytes.Data, analytics)
				if err != nil {
					analytics = &Analytics{}
				}
			}
		}
		// Increment counters
		dist.Count += 1
		dist.Reactions += int64(len(analytics.Reactions))
		// Process reactions
		for _, reaction := range analytics.Reactions {
			for _, usr := range reaction.Usernames {
				// Did we see this reaction's user yet?
				if _, ok := reactors[usr]; ok {
					reactors[usr] += 1
				} else {
					reactors[usr] = 1
				}
			}
		}
		// Did we see this msg's user yet?
		if _, ok := contributors[msg.Username]; ok {
			contributors[msg.Username] += 1
		} else {
			contributors[msg.Username] = 1
		}
	}
	// Attach contributors to response
	for usr, cnt := range contributors {
		dist.Contributors = append(dist.Contributors, &MessageContributor{
			Username:  usr,
			Count:     cnt,
			Reactions: reactors[usr],
		})
	}
	// Sort by count
	sort.SliceStable(
		dist.Contributors, func(i, j int) bool {
			return dist.Contributors[i].Count > dist.Contributors[j].Count
		},
	)
	return dist
}
