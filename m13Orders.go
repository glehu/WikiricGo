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
	"time"
)

const OrderDB = "m13"

const OrderStateOpen = "open"
const OrderStateDone = "done"
const OrderStateCancelled = "cancelled"

const OrderBillingStateOpen = "open"
const OrderBillingStatePaidPartially = "partially"
const OrderBillingStatePaid = "paid"
const OrderBillingStateRefund = "refund"

const OrderDeliveryStateOpen = "open"
const OrderDeliveryStateInDelivery = "delivery"
const OrderDeliveryStateDelivered = "delivered"
const OrderDeliveryStateFailed = "failed"
const OrderDeliveryStateReturn = "return"

type Order struct {
	StoreUUID      string          `json:"pid"`
	Username       string          `json:"usr"`
	Billing        BillingAddress  `json:"billing"`
	Delivery       DeliveryAddress `json:"delivery"`
	TimeCreated    string          `json:"ts"`
	State          string          `json:"state"`
	BillingState   string          `json:"bstate"`
	DeliveryState  string          `json:"dstate"`
	ItemPositions  []ItemPosition  `json:"items"`
	CustomerNote   string          `json:"cnote"`
	NetTotal       float64         `json:"net"`
	GrossTotal     float64         `json:"gross"`
	BillingHistory []BillingEntry  `json:"bhist"`
}

type OrderEntry struct {
	UUID string `json:"uid"`
	*Order
}

type OrderList struct {
	Orders []*OrderEntry `json:"orders"`
}

type BillingAddress struct {
	Country      string `json:"country"`
	PostalCode   string `json:"postcode"`
	StateArea    string `json:"stateArea"`
	City         string `json:"city"`
	Street       string `json:"street"`
	HouseNumber  string `json:"number"`
	FloorNumber  string `json:"floor"`
	FirstName    string `json:"first"`
	LastName     string `json:"last"`
	CompanyName  string `json:"company"`
	Email        string `json:"email"`
	CustomerNote string `json:"cnote"`
}

type DeliveryAddress struct {
	Country      string `json:"country"`
	PostalCode   string `json:"postcode"`
	StateArea    string `json:"stateArea"`
	City         string `json:"city"`
	Street       string `json:"street"`
	HouseNumber  string `json:"number"`
	FloorNumber  string `json:"floor"`
	FirstName    string `json:"first"`
	LastName     string `json:"last"`
	CompanyName  string `json:"company"`
	Email        string `json:"email"`
	CustomerNote string `json:"cnote"`
}

type ItemPosition struct {
	ItemUUID        string          `json:"itemId"`
	Name            string          `json:"t"`
	Amount          float64         `json:"amt"`
	NetPrice        float64         `json:"net"`
	VATPercent      float64         `json:"vatp"`
	DiscountPercent float64         `json:"discP"`
	DiscountFixed   float64         `json:"discF"`
	CustomerNote    string          `json:"cnote"`
	Variations      []ItemVariation `json:"vars"`
}

type BillingEntry struct {
	DateTime string  `json:"ts"`
	Total    float64 `json:"total"`
}

type VATCalculationMap struct {
	Positions map[float64]float64 // Key: VATPercent, Value: Slice of NetPrice
}

func (db *GoDB) ProtectedOrdersEndpoints(r chi.Router, tokenAuth *jwtauth.JWTAuth,
	mainDB *GoDB, connector *Connector,
) {
	r.Route("/orders/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		// ###########
		// ### GET ###
		// ###########
		r.Get("/orders", db.handleOrdersGetOwn())
		r.Get("/commissions", db.handleOrdersGetCommissions(mainDB))
		r.Get("/cancel/{orderID}", db.handleOrderCancel(mainDB))
	})
}

func (a *Order) Bind(_ *http.Request) error {
	if a.StoreUUID == "" {
		return errors.New("missing storeUUID")
	}
	if a.ItemPositions == nil || len(a.ItemPositions) < 1 {
		return errors.New("missing items")
	}
	if a.Billing.LastName == "" && a.Delivery.LastName == "" {
		return errors.New("missing name")
	}
	return nil
}

func CalculateOrder(rapidDB *GoDB, order *Order, sanitize bool) error {
	// Get prices for all ordered items
	var ok bool
	var itemResp *EntryResponse
	var item *Item
	var netTotal, grossTotal float64
	vatCalc := VATCalculationMap{Positions: map[float64]float64{}}
	// ### CALCULATION First run: Calculate net prices and add to sum
	// We also sanitize the order positions
	for ix, itemTmp := range order.ItemPositions {
		if itemTmp.ItemUUID == "" {
			continue
		}
		// Retrieve item
		itemResp, ok = rapidDB.Read(ItemDB, itemTmp.ItemUUID)
		if !ok {
			return errors.New(fmt.Sprintf("cannot process item %s", itemTmp.ItemUUID))
		}
		item = &Item{}
		err := json.Unmarshal(itemResp.Data, item)
		if err != nil {
			return errors.New(fmt.Sprintf("cannot process item %s", itemTmp.ItemUUID))
		}
		if sanitize {
			// Sanitize (e.g. discounts as the user should not be able to set them on their own
			order.ItemPositions[ix].DiscountPercent = 0
			order.ItemPositions[ix].DiscountFixed = 0
			if order.ItemPositions[ix].Name == "" {
				order.ItemPositions[ix].Name = item.Name
			}
		}
		// TODO: Discount
		// Set current item net price
		order.ItemPositions[ix].NetPrice = item.NetPrice
		order.ItemPositions[ix].VATPercent = item.VATPercent
		// Add item variation costs
		var foundVarVar bool
		for _, variation := range order.ItemPositions[ix].Variations {
			// Does the provided variation contain a chosen variation?
			if variation.Variations != nil && len(variation.Variations) > 0 {
				// Find variation type in item
				foundVarVar = false
				for _, itVar := range item.Variations {
					if itVar.Name == variation.Name {
						// Find variation variation in item
						for _, itVarVar := range itVar.Variations {
							if itVarVar.StringValue == variation.Variations[0].StringValue {
								// Add variation cost to position
								order.ItemPositions[ix].NetPrice += itVarVar.NetPrice
								foundVarVar = true
								break
							}
						}
						if foundVarVar {
							break
						}
					}
				}
			}
		}
		// Multiply by amount
		order.ItemPositions[ix].NetPrice = order.ItemPositions[ix].NetPrice * order.ItemPositions[ix].Amount
		// Add to sum
		netTotal += order.ItemPositions[ix].NetPrice
		// VAT?
		if item.VATPercent > 0 {
			vatCalc.Positions[item.VATPercent] += order.ItemPositions[ix].NetPrice
		}
	}
	// ### CALCULATION Second run: Calculate gross prices and add to sum
	for vat, net := range vatCalc.Positions {
		grossTotal += net + (net * vat)
	}
	order.GrossTotal = grossTotal
	order.NetTotal = netTotal
	return nil
}

func NotifyBuyerOrderConfirmation(store *Store, order *Order, orderID string,
	rapidDB *GoDB, connector *Connector, emailClient *EmailClient,
) error {
	to := []string{order.Billing.Email}
	subject := "Order Confirmation"
	msg := &strings.Builder{}
	msg.WriteString("<h1>Your order has been confirmed!</h1>")
	appendOrderEmail(msg, order, orderID)
	appendOrderBankDetails(msg, store)
	// Send mail
	_ = emailClient.sendMail(to, []byte(subject), []byte(msg.String()))
	// Notification
	notification := &Notification{
		Title: "Order Confirmed",
		Description: fmt.Sprintf(
			"Order (%s) from %s was commissioned.", orderID, order.TimeCreated),
		Type:              "info",
		TimeCreated:       TimeNowIsoString(),
		RecipientUsername: order.Username,
		ClickAction:       "",
		ClickModule:       "",
		ClickUUID:         "",
	}
	jsonNotification, err := json.Marshal(notification)
	if err == nil {
		_, _ = rapidDB.Insert(NotifyDB, jsonNotification, map[string]string{
			"usr": FIndex(order.Username),
		})
	}
	return nil
}

func NotifyBuyerOrderStateChange(
	stateType, stateValue, message string,
	store *Store, order *Order, orderID string,
	rapidDB *GoDB, connector *Connector, emailClient *EmailClient,
) error {
	to := []string{order.Billing.Email}
	subject := fmt.Sprintf("Order %s State Changed to %s", stateType, stateValue)
	msg := &strings.Builder{}
	msg.WriteString(fmt.Sprintf("<h1>%s</h1>", message))
	appendOrderEmail(msg, order, orderID)
	appendOrderBankDetails(msg, store)
	// Send mail
	_ = emailClient.sendMail(to, []byte(subject), []byte(msg.String()))
	// Notification
	notification := &Notification{
		Title:             fmt.Sprintf("Order %s State Changed to %s", stateType, stateValue),
		Description:       message,
		Type:              "info",
		TimeCreated:       TimeNowIsoString(),
		RecipientUsername: order.Username,
		ClickAction:       "",
		ClickModule:       "",
		ClickUUID:         "",
	}
	jsonNotification, err := json.Marshal(notification)
	if err == nil {
		_, _ = rapidDB.Insert(NotifyDB, jsonNotification, map[string]string{
			"usr": FIndex(order.Username),
		})
	}
	return nil
}

func NotifyStoreOwnerOrderConfirmation(store *Store, order *Order, orderID string,
	rapidDB *GoDB, connector *Connector, emailClient *EmailClient,
) error {
	to := []string{order.Billing.Email}
	subject := "New Order"
	msg := &strings.Builder{}
	msg.WriteString("<h1>A new order has been commissioned!</h1>")
	appendOrderEmail(msg, order, orderID)
	// Send mail
	_ = emailClient.sendMail(to, []byte(subject), []byte(msg.String()))
	// Notification
	notification := &Notification{
		Title:             "New Order",
		Description:       "A new commission came in!",
		Type:              "info",
		TimeCreated:       TimeNowIsoString(),
		RecipientUsername: store.Username,
		ClickAction:       "",
		ClickModule:       "",
		ClickUUID:         "",
	}
	jsonNotification, err := json.Marshal(notification)
	if err != nil {
		return nil
	}
	notificationUUID, _ := rapidDB.Insert(NotifyDB, jsonNotification, map[string]string{
		"usr": FIndex(store.Username),
	})
	// Now send a message via the connector
	connector.SessionsMu.RLock()
	defer connector.SessionsMu.RUnlock()
	session, ok := connector.Sessions.Get(store.Username)
	if !ok {
		return nil
	}
	cMSG := &ConnectorMsg{
		Type:          "[s:NOTIFICATION]",
		Action:        "commission",
		ReferenceUUID: notificationUUID,
		Username:      store.Username,
		Message:       "A new commission came in!",
	}
	_ = WSSendJSON(session.Conn, session.Ctx, cMSG)
	return nil
}

func appendOrderEmail(msg *strings.Builder, order *Order, orderID string) {
	orderDateTime, err := IsoStringToTime(order.TimeCreated)
	if err != nil {
		orderDateTime = time.Now().UTC()
	}
	orderDate := orderDateTime.Format(time.RFC822)
	msg.WriteString("<br>")
	msg.WriteString(fmt.Sprintf("<p>Order number: %s</p>", orderID))
	msg.WriteString(fmt.Sprintf("<p>Order date: %s</p>", orderDate))
	msg.WriteString("<br>")
	msg.WriteString("<p>Order Positions:</p>")
	msg.WriteString("<br>")
	msg.WriteString("<table>") // POS TABLE START
	msg.WriteString("<tr>")    // POS TABLE HEADER START
	msg.WriteString("<th>#</th>")
	msg.WriteString("<th>Amount</th>")
	msg.WriteString("<th>Description</th>")
	msg.WriteString("<th>Gross Total</th>")
	msg.WriteString("<th>Net Total</th>")
	msg.WriteString("<tr>") // POS TABLE HEADER END
	var gross float64
	for ix, item := range order.ItemPositions {
		gross = item.NetPrice * (1 + item.VATPercent)
		msg.WriteString("<tr>") // POS TABLE POS START
		msg.WriteString(fmt.Sprintf("<td>%d</td>", ix))
		msg.WriteString(fmt.Sprintf("<td>%.1f</td>", item.Amount))
		msg.WriteString(fmt.Sprintf("<td>%s</td>", item.Name))
		msg.WriteString(fmt.Sprintf("<td>%f</td>", gross))
		msg.WriteString(fmt.Sprintf("<td>%f (%f %s VAT)</td>", item.NetPrice, item.VATPercent*100, "%"))
		msg.WriteString("<tr>") // POS TABLE POS END
	}
	msg.WriteString("</table>") // POS TABLE END
	msg.WriteString("<br>")
	msg.WriteString(fmt.Sprintf("<p>Net Total: %.2f</p>", order.NetTotal))
	msg.WriteString(fmt.Sprintf("<p>VAT Total: %.2f</p>", order.GrossTotal-order.NetTotal))
	msg.WriteString("<br>")
	msg.WriteString(fmt.Sprintf("<p>Gross Total: %.2f</p>", order.GrossTotal))
	msg.WriteString("<br>")
	msg.WriteString("<br>")
	msg.WriteString("<p>Disclaimer: This is an order confirmation email, not an invoice." +
		"wikiric stores are being implemented at this moment " +
		"thus making this email not an official invoice to be used legally. " +
		"Please ask the store owner for a real invoice if needed. Thank you.</p>")
	msg.WriteString("<br>")
}

func appendOrderBankDetails(msg *strings.Builder, store *Store) {
	msg.WriteString("<br>")
	msg.WriteString("<p>Store Bank Details:</p>")
	msg.WriteString(fmt.Sprintf("<p>Name: %s</p>", store.BankDetails.Name))
	msg.WriteString(fmt.Sprintf("<p>Bank Name: %s</p>", store.BankDetails.BankName))
	msg.WriteString(fmt.Sprintf("<p>IBAN: %s</p>", store.BankDetails.IBAN))
	msg.WriteString(fmt.Sprintf("<p>SWIFT Code: %s</p>", store.BankDetails.SwiftCode))
	msg.WriteString("<br>")
}

func (db *GoDB) handleOrdersGetOwn() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve user's orders
		query := FIndex(user.Username)
		resp, err := db.Select(OrderDB, map[string]string{
			"usr": query}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		orderList := make([]*OrderEntry, 0)
		response := <-resp
		if len(response) < 1 {
			render.JSON(w, r, orderList)
			return
		}
		var order *Order
		for _, orderResp := range response {
			order = &Order{}
			err = json.Unmarshal(orderResp.Data, order)
			if err != nil {
				continue
			}
			orderList = append(orderList, &OrderEntry{
				Order: order,
				UUID:  orderResp.uUID,
			})
		}
		render.JSON(w, r, orderList)
	}
}

func (db *GoDB) handleOrdersGetCommissions(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve user's store
		query := FIndex(user.Username)
		resp, err := mainDB.Select(StoreDB, map[string]string{
			"usr": query,
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
		store := &Store{}
		err = json.Unmarshal(response[0].Data, store)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Retrieve commissions
		query = fmt.Sprintf("%s;%s", response[0].uUID, OrderStateOpen)
		resp, err = db.Select(OrderDB, map[string]string{
			"pid-state": query}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		orderList := &OrderList{Orders: make([]*OrderEntry, 0)}
		response = <-resp
		if len(response) < 1 {
			render.JSON(w, r, orderList)
			return
		}
		var order *Order
		for _, orderResp := range response {
			order = &Order{}
			err = json.Unmarshal(orderResp.Data, order)
			if err != nil || order.State == OrderStateCancelled { // TODO: Allow cancelled with query parameter
				continue
			}
			orderList.Orders = append(orderList.Orders, &OrderEntry{
				Order: order,
				UUID:  orderResp.uUID,
			})
		}
		render.JSON(w, r, orderList)
	}
}

func (db *GoDB) handleOrderCancel(mainDB *GoDB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		orderID := chi.URLParam(r, "orderID")
		if orderID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		// Retrieve order
		response, txn := db.Get(OrderDB, orderID)
		if response == nil || txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		order := &Order{}
		err := json.Unmarshal(response.Data, order)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check if order belongs to caller's store
		if order.StoreUUID != "" {
			orderResp, ok := mainDB.Read(StoreDB, order.StoreUUID)
			if !ok {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			store := &Store{}
			err = json.Unmarshal(orderResp.Data, order)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			if store.Username != user.Username {
				http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
		}
		// Cancel order
		order.State = OrderStateCancelled
		// Update
		jsonEntry, err := json.Marshal(order)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(OrderDB, txn, response.uUID, jsonEntry, map[string]string{
			"usr":       FIndex(user.Username),
			"pid-state": fmt.Sprintf("%s;%s", order.StoreUUID, order.State),
		})
		// err = NotifyBuyerOrderStateChange("Commission", "Cancelled",
		//  store, request, uUID, notificationDB, connector, emailClient)
	}
}
