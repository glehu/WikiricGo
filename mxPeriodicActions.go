package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"firebase.google.com/go/messaging"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"net/http"
	"strconv"
	"time"
)

const PeriodDB = "mxpa"

type PeriodicAction struct {
	NotificationTemplate Notification            `json:"tmpl"`
	Username             string                  `json:"usr"`
	Topic                string                  `json:"topic"`
	Recipients           []NotificationRecipient `json:"rec"`
	ChatGroupID          string                  `json:"chatId"`
	ChatGroupRole        []string                `json:"roles"`
	TriggerDateTime      string                  `json:"due"`
	TriggerDateTimeUnix  int64                   `json:"dunx"`
	IsReoccurring        bool                    `json:"isre"`
	ReoccurringInterval  string                  `json:"ival"`
	ReoccurringAmount    int64                   `json:"amt"`
	Reference            string                  `json:"ref"`
	WebhookURLs          []Webhook               `json:"hooks"`
	MuteNotifications    bool                    `json:"mute"`
}

type PeriodicActionEntry struct {
	UUID string `json:"uid"`
	*PeriodicAction
}

type NotificationRecipient struct {
	Username string `json:"usr"`
	FCMToken string `json:"fcm"`
}

type PeriodicActionsResponse struct {
	PeriodicActions []*PeriodicActionEntry `json:"periodic"`
}

type Webhook struct {
	URL         string `json:"url"`
	WithMessage bool   `json:"msg"`
}

func (db *GoDB) ProtectedPeriodicActionsEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth, mainDB *GoDB, connector *Connector,
) {
	r.Route("/periodic/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/create", db.handlePeriodicActionCreate())
		r.Post("/mod/{periodicID}", db.handlePeriodicActionModification())
		// ###########
		// ### GET ###
		// ###########
		r.Get("/read", db.handlePeriodicActionsGet())
		r.Get("/delete/{periodicID}", db.handlePeriodicActionDelete())
	})
}

const PeriodInterval = time.Minute * 1

func (db *GoDB) StartPeriodicLoop(
	done chan bool, dbList *Databases, connector *Connector, fcmClient *messaging.Client,
) {
	ticker := time.NewTicker(PeriodInterval)
	go db.tickLoop(ticker, done, dbList, connector, fcmClient)
	fmt.Println(":: Periodic Loop Started")
}

func (db *GoDB) tickLoop(
	ticker *time.Ticker, done chan bool, dbList *Databases, connector *Connector, fcmClient *messaging.Client,
) {
	// The hour counter decrements once per minute until it reaches 0
	hourCounter := 60
	for {
		select {
		case <-done:
			fmt.Println(":: Periodic Loop Stopped")
			return
		case <-ticker.C:
			hourCounter -= 1
			go db.triggerActions(dbList, connector, fcmClient)
			// Trigger hourly actions here
			if hourCounter == 0 {
				hourCounter = 60
				// Garbage collect the database value log every hour
				go gcDatabases(dbList)
			}
		}
	}
}

func gcDatabases(dbList *Databases) {
	fmt.Println(":: GC DB: START " + TimeNowIsoString())
	_ = dbList.Map["main"].db.RunValueLogGC(0.5)
	_ = dbList.Map["rapid"].db.RunValueLogGC(0.5)
	fmt.Println(":: GC DB: DONE  " + TimeNowIsoString())
}

func (db *GoDB) triggerActions(dbList *Databases, connector *Connector, fcmClient *messaging.Client) {
	// Actions:
	go db.periodicCheck(connector, fcmClient)
	go dbList.Map["msg"].periodicCheckMessages()
}

func (db *GoDB) periodicCheckMessages() {
	return
}

func (db *GoDB) periodicCheck(connector *Connector, fcmClient *messaging.Client) {
	var respNow, respLast chan *EntryResponse
	var err error
	// Retrieve periodic actions that are due
	// We will query periodic actions by day and a portion of the time string as follows:
	// (Example with 30 min interval assuming neither hour-switch nor day-switch)
	//    Example Date:   2006-01-02T15:34:05Z
	//    Index Query 1:  2006-01-02T15
	//    Last Period:    2006-01-02T15:04:05Z
	//    Index Query 2:  (none)
	// (Example with 30 min interval assuming hour-switch but no day-switch)
	//    Example Date:   2006-01-02T15:04:05Z
	//    Index Query 1:  2006-01-02T15
	//    Last Period:    2006-01-02T14:34:05Z
	//    Index Query 2:  2006-01-02T14
	// (Example with 30 min interval assuming day-switch is happening)
	//    Example Date:   2006-01-02T00:04:05Z
	//    Index Query 1:  2006-01-02T00
	//    Last Period:    2006-01-01T23:34:05Z
	//    Index Query 2:  2006-01-01T23
	twoQueries := false
	now := time.Now().UTC()
	last := now.Add(PeriodInterval * -1)
	// Generate ISO timestamps
	nowISO := TimeToIsoString(now)
	lastISO := TimeToIsoString(last)
	if now.Hour() != last.Hour() {
		twoQueries = true
	}
	// Generate and start index queries
	nowQuery := nowISO[0:13] // YYYY-MM-DDTHH
	if twoQueries {
		lastQuery := lastISO[0:13] // YYYY-MM-DDTHH
		respLast, _, err = db.SSelect(PeriodDB, map[string]string{"due": lastQuery},
			nil, 10, 100, true)
		if err != nil {
			return
		}
	}
	respNow, _, err = db.SSelect(PeriodDB, map[string]string{"due": nowQuery},
		nil, 10, 100, true)
	if err != nil {
		return
	}
	// Prepare response list
	var action *PeriodicAction
	periodicActions := make([]*PeriodicActionEntry, 0)
	// Collect responses
	if twoQueries {
		periodicActions = checkAndAddDuePeriodicActions(respLast, periodicActions, action, now)
	}
	periodicActions = checkAndAddDuePeriodicActions(respNow, periodicActions, action, now)
	// Process
	db.processPeriodicActions(periodicActions, connector, fcmClient)
	return
}

func (db *GoDB) processPeriodicActions(
	list []*PeriodicActionEntry, connector *Connector, fcmClient *messaging.Client,
) {
	if len(list) < 1 {
		return
	}
	for _, action := range list {
		go db.processSinglePeriodicAction(action, connector, fcmClient)
	}
}

func (db *GoDB) processSinglePeriodicAction(
	action *PeriodicActionEntry, connector *Connector, fcmClient *messaging.Client,
) {
	if action.NotificationTemplate.Type != "" {
		// Create notification for each recipient
		fcmTokens := make([]string, 0)
		connector.SessionsMu.RLock()
		for _, recip := range action.Recipients {
			if recip.FCMToken != "" {
				fcmTokens = append(fcmTokens, recip.FCMToken)
			}
			notification := &Notification{
				Title:             fmt.Sprintf("Reminder: %s", action.NotificationTemplate.Title),
				Description:       fmt.Sprintf("%s", action.NotificationTemplate.Description),
				Type:              action.NotificationTemplate.Type,
				TimeCreated:       TimeNowIsoString(),
				RecipientUsername: recip.Username,
				ClickAction:       action.NotificationTemplate.ClickAction,
				ClickModule:       action.NotificationTemplate.ClickModule,
				ClickUUID:         action.NotificationTemplate.ClickUUID,
			}
			jsonNotification, err := json.Marshal(notification)
			if err != nil {
				continue
			}
			notificationUUID, err := db.Insert(NotifyDB, jsonNotification, map[string]string{
				"usr": FIndex(recip.Username),
			})
			if err != nil {
				continue
			}
			// Now send a message via the connector
			session, ok := connector.Sessions.Get(recip.Username)
			if !ok {
				continue
			}
			cMSG := &ConnectorMsg{
				Type:          "[s:NOTIFICATION]",
				Action:        "due",
				ReferenceUUID: notificationUUID,
				Username:      "",
				Message:       action.NotificationTemplate.Description,
			}
			_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
		}
		connector.SessionsMu.RUnlock()
		// Are there push notifications to be sent?
		if len(fcmTokens) > 0 {
			go sendPushNotifications(fcmTokens, action.NotificationTemplate, action.TriggerDateTime, fcmClient)
		}
	}
	// Do we need to call webhooks?
	if len(action.WebhookURLs) > 0 {
		client := http.Client{}
		var body []byte
		var reader *bytes.Reader
		for _, webhook := range action.WebhookURLs {
			if webhook.URL != "" {
				var httpResp *http.Response
				var httpErr error
				if webhook.WithMessage {
					// POST
					body = []byte(fmt.Sprintf(
						"Reminder: %s - %s - sent from wikiric",
						action.NotificationTemplate.Title,
						action.NotificationTemplate.Description))
					reader = bytes.NewReader(body)
					httpResp, httpErr = client.Post(webhook.URL, "text/plain", reader)
				} else {
					// GET
					httpResp, httpErr = client.Get(webhook.URL)
				}
				// Check if errors occurred
				if httpErr != nil || (httpResp.StatusCode >= 400 && httpResp.StatusCode < 600) {
					// Error or HTTP error code occurred -> Notify action owner
					db.notifyWebhookFailed(webhook, action, connector, fcmClient)
				}
			}
		}
	}
	// Is this action reoccurring? If not, then delete it now
	if action.IsReoccurring == false || action.ReoccurringAmount < 1 {
		_ = db.Delete(PeriodDB, action.UUID, []string{"usr", "due", "ref"})
		return
	}
	// Replace current trigger date with next period specified
	dueDate, err := IsoStringToTime(action.TriggerDateTime)
	if err != nil {
		return
	}
	duration, err := time.ParseDuration(action.ReoccurringInterval)
	if err != nil {
		return
	}
	dueDate = dueDate.UTC().Add(duration)
	action.TriggerDateTime = TimeToIsoString(dueDate)
	// Subtract one of amount
	action.ReoccurringAmount -= 1
	// Update action
	jsonAction, err := json.Marshal(action)
	_, txn := db.Get(PeriodDB, action.UUID)
	_ = db.Update(PeriodDB, txn, action.UUID, jsonAction, map[string]string{"due": action.TriggerDateTime})
}

func (db *GoDB) notifyWebhookFailed(
	webhook Webhook, action *PeriodicActionEntry,
	connector *Connector, fcmClient *messaging.Client,
) {
	// Create notification for each recipient
	fcmTokens := make([]string, 0)
	connector.SessionsMu.RLock()
	title := "Webhook Failed"
	if action.NotificationTemplate.Title != "" {
		title += fmt.Sprintf(": %s", action.NotificationTemplate.Title)
	}
	for _, recip := range action.Recipients {
		if recip.FCMToken != "" {
			fcmTokens = append(fcmTokens, recip.FCMToken)
		}
		notification := &Notification{
			Title:             title,
			Description:       fmt.Sprintf("%s", webhook.URL),
			Type:              "hook_status",
			TimeCreated:       TimeNowIsoString(),
			RecipientUsername: recip.Username,
			ClickAction:       "",
			ClickModule:       "",
			ClickUUID:         "",
		}
		jsonNotification, err := json.Marshal(notification)
		if err != nil {
			continue
		}
		notificationUUID, err := db.Insert(NotifyDB, jsonNotification, map[string]string{
			"usr": FIndex(recip.Username),
		})
		if err != nil {
			continue
		}
		// Now send a message via the connector
		session, ok := connector.Sessions.Get(recip.Username)
		if !ok {
			continue
		}
		cMSG := &ConnectorMsg{
			Type:          "[s:NOTIFICATION]",
			Action:        "hook_status",
			ReferenceUUID: notificationUUID,
			Username:      "",
			Message:       action.NotificationTemplate.Description,
		}
		_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	}
	connector.SessionsMu.RUnlock()
	// Are there push notifications to be sent?
	if len(fcmTokens) > 0 {
		go sendPushNotifications(fcmTokens, action.NotificationTemplate, action.TriggerDateTime, fcmClient)
	}
}

func sendPushNotifications(
	fcmTokens []string, notification Notification, dueDate string, fcmClient *messaging.Client,
) {
	_, _ = fcmClient.SendMulticast(context.Background(), &messaging.MulticastMessage{
		Notification: &messaging.Notification{
			Title: fmt.Sprintf("[%s]: %s", dueDate, notification.Title),
			Body:  notification.Description,
		},
		Data: map[string]string{
			"dlType": "periodic",
			"dlDest": "",
		},
		Webpush: &messaging.WebpushConfig{
			FcmOptions: &messaging.WebpushFcmOptions{
				Link: "",
			},
		},
		Tokens: fcmTokens,
	})
}

func checkAndAddDuePeriodicActions(
	response chan *EntryResponse, list []*PeriodicActionEntry, actionTmp *PeriodicAction, now time.Time,
) []*PeriodicActionEntry {
	var dueDate time.Time
	for value := range response {
		actionTmp = &PeriodicAction{}
		err := json.Unmarshal(value.Data, actionTmp)
		// Skip if json unmarshal failed...
		if err != nil {
			continue
		}
		// ...or due time has not been reached
		dueDate, err = IsoStringToTime(actionTmp.TriggerDateTime)
		if err != nil {
			continue
		}
		// Invalid if day, hour and minute are greater than the current time of execution
		if now.Before(dueDate) {
			continue
		}
		// Append if it matched all criteria
		list = append(list, &PeriodicActionEntry{
			UUID:           value.uUID,
			PeriodicAction: actionTmp,
		})
	}
	return list
}

func (db *GoDB) handlePeriodicActionsGet() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		actions := PeriodicActionsResponse{PeriodicActions: make([]*PeriodicActionEntry, 0)}
		// Check if user wants to query reference UUID
		refQuery := r.URL.Query().Get("qref")
		var respActions chan []*EntryResponse
		var err error
		if refQuery != "" {
			// Retrieve all periodic actions of this reference UUID
			respActions, err = db.Select(PeriodDB, map[string]string{"ref": FIndex(refQuery)}, nil)
		} else {
			// Retrieve all periodic actions of this user
			respActions, err = db.Select(PeriodDB, map[string]string{"usr": FIndex(user.Username)}, nil)
		}
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		responseActions := <-respActions
		if len(responseActions) < 1 {
			// Respond
			render.JSON(w, r, actions)
			return
		}
		var action *PeriodicAction
		for _, entry := range responseActions {
			action = &PeriodicAction{}
			err = json.Unmarshal(entry.Data, action)
			if err != nil {
				continue
			}
			actions.PeriodicActions = append(actions.PeriodicActions, &PeriodicActionEntry{
				UUID:           entry.uUID,
				PeriodicAction: action,
			})
		}
		render.JSON(w, r, actions)
	}
}

func (db *GoDB) handlePeriodicActionDelete() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		periodicID := chi.URLParam(r, "periodicID")
		if periodicID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Read(PeriodDB, periodicID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		action := &PeriodicAction{}
		err := json.Unmarshal(response.Data, action)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// If we're the owner of this action, delete it...
		if user.Username == action.Username {
			_ = db.Delete(PeriodDB, periodicID, []string{"usr", "due", "ref"})
			return
		}
		// ...otherwise check if we're a recipient and remove us from this
		isRecipient := false
		ix := 0
		for i, recipient := range action.Recipients {
			if user.Username == recipient.Username {
				isRecipient = true
				ix = i
				break
			}
		}
		if !isRecipient {
			return
		}
		response, txn := db.Get(PeriodDB, periodicID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		action = &PeriodicAction{}
		err = json.Unmarshal(response.Data, action)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Remove user from recipients
		action.Recipients = append(action.Recipients[:ix], action.Recipients[ix+1:]...)
		jsonEntry, err := json.Marshal(action)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_ = db.Update(PeriodDB, txn, periodicID, jsonEntry, map[string]string{})
	}
}

func (db *GoDB) handlePeriodicActionModification() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		periodicID := chi.URLParam(r, "periodicID")
		if periodicID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Get Periodic Action
		resp, txn := db.Get(PeriodDB, periodicID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		action := &PeriodicAction{}
		err := json.Unmarshal(resp.Data, action)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if user has right to modify this action
		if action.Username != user.Username {
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
				action.TriggerDateTime = request.NewValue
			} else if request.Field == "amount" {
				newAmount, err := strconv.ParseInt(request.NewValue, 10, 64)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
					return
				}
				action.ReoccurringAmount = newAmount
			}
			// Store
			jsonEntry, err := json.Marshal(action)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			err = db.Update(PeriodDB, txn, periodicID, jsonEntry, map[string]string{})
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
	}
}

func (a *PeriodicAction) Bind(_ *http.Request) error {
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

func (db *GoDB) handlePeriodicActionCreate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &PeriodicAction{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Parse trigger date time
		triggerTime, err := IsoStringToTime(request.TriggerDateTime)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Convert date to UTC date to avoid weird timezone problems
		triggerTime = triggerTime.UTC()
		// Generate unix timestamp for due date
		request.TriggerDateTimeUnix = triggerTime.Unix()
		// Write back to request
		request.TriggerDateTime = TimeToIsoString(triggerTime)
		// Sanitize
		if request.Username == "" {
			request.Username = user.Username
		}
		if request.WebhookURLs == nil {
			request.WebhookURLs = make([]Webhook, 0)
		}
		if request.ReoccurringAmount > 0 {
			request.IsReoccurring = true
		}
		// Store
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		_, err = db.Insert(PeriodDB, jsonEntry, map[string]string{
			"usr": FIndex(user.Username),
			"due": request.TriggerDateTime,
			"ref": FIndex(request.Reference),
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}
