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
	"slices"
	"sort"
)

type Process struct {
	Name                 string   `json:"t"`
	Description          string   `json:"desc"`
	Author               string   `json:"usr"`
	Categories           []string `json:"cats"`
	RowIndex             float64  `json:"row"`
	PreviousUUID         []string `json:"prev"`
	NextUUID             []string `json:"next"`
	TimeCreated          string   `json:"ts"`
	IsPublic             bool     `json:"pub"`
	KnowledgeUUID        string   `json:"pid"`
	IsRootNode           bool     `json:"root"`
	TaskUUID             string   `json:"tid"`
	AnalyticsUUID        string   `json:"ana"` // Views, likes etc. will be stored in a separate database
	ProjectUUID          string   `json:"proj"`
	Collaborators        []string `json:"coll"`
	ThumbnailURL         string   `json:"iurl"`
	ThumbnailAnimatedURL string   `json:"iurla"`
	BannerURL            string   `json:"burl"`
	BannerAnimatedURL    string   `json:"burla"`
}

type ProcessContainer struct {
	*Process
	*Analytics
	UUID string `json:"uid"`
}

type ProcessPathContainer struct {
	Process  *ProcessContainer
	Children []*ProcessContainer
}

type ProcessPath struct {
	Processes []*ProcessPathContainer
}

type ProcessModification struct {
	Field    string  `json:"field"`
	NewValue string  `json:"new"`
	FromUUID string  `json:"fromId"`
	ToUUID   string  `json:"toId"`
	RowIndex float64 `json:"row"`
}

func OpenProcessDatabase() *GoDB {
	db := OpenDB("processes")
	return db
}

func (db *GoDB) ProtectedProcessEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB, analyticsDB *GoDB, connector *Connector,
) {
	r.Route("/process/private", func(r chi.Router) {
		r.Post("/create", db.handleProcessCreate(
			chatGroupDB, chatMemberDB, notificationDB, knowledgeDB, connector))
		r.Post("/edit/{processID}", db.handleProcessEdit(
			chatGroupDB, chatMemberDB, notificationDB, knowledgeDB, connector))
		r.Get("/path/{processID}", db.handleProcessGetPath(
			chatGroupDB, chatMemberDB, notificationDB, knowledgeDB, connector))
		r.Get("/delete/{processID}", db.handleProcessDelete(
			chatGroupDB, chatMemberDB, notificationDB, knowledgeDB, connector))
	})
}

func (p *Process) Bind(_ *http.Request) error {
	if p.Name == "" {
		return errors.New("missing name")
	}
	if p.KnowledgeUUID == "" {
		return errors.New("missing knowledge id")
	}
	return nil
}

func (p *Process) update(db *GoDB, txn *badger.Txn, id string) error {
	jsonEntry, err := json.Marshal(p)
	if err != nil {
		return err
	}
	err = db.Update(txn, id, jsonEntry, map[string]string{
		"knowledgeID": p.KnowledgeUUID,
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) handleProcessCreate(
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		// Retrieve POST payload
		request := &Process{}
		if err := render.Bind(r, request); err != nil {
			fmt.Println(err)
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
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
		if request.Collaborators == nil {
			request.Collaborators = make([]string, 0)
		}
		if request.Categories == nil {
			request.Categories = make([]string, 0)
		}
		if request.PreviousUUID == nil {
			request.PreviousUUID = make([]string, 0)
		}
		if request.NextUUID == nil {
			request.NextUUID = make([]string, 0)
		}
		jsonEntry, err := json.Marshal(request)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		uUID, err := db.Insert(jsonEntry, map[string]string{
			"knowledgeID": request.KnowledgeUUID,
		})
		resp, txn := db.Get(uUID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		defer txn.Discard()
		process := &Process{}
		err = json.Unmarshal(resp.Data, process)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.rearrangeProcesses(process, resp)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Update
		err = process.update(db, txn, resp.uUID)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Respond to client
		_, _ = fmt.Fprintln(w, uUID)
	}
}

func (db *GoDB) rearrangeProcesses(process *Process, rMP *EntryResponse) error {
	var isMainNode bool
	neighborless := false
	if len(process.NextUUID) > 0 {
		// Next nodes provided -> main node
		isMainNode = true
		if len(process.PreviousUUID) > 0 {
			// Previous and next nodes -> links need to be rebuilt
			// Get previous node
			rP, txnP := db.Get(process.PreviousUUID[0])
			if txnP == nil {
				return errors.New("err")
			}
			defer txnP.Discard()
			prev := &Process{}
			err := json.Unmarshal(rP.Data, prev)
			if err != nil {
				return errors.New("err")
			}
			// Get next node
			rN, txnN := db.Get(process.NextUUID[0])
			if txnN == nil {
				return errors.New("err")
			}
			defer txnN.Discard()
			next := &Process{}
			err = json.Unmarshal(rN.Data, next)
			if err != nil {
				return errors.New("err")
			}
			// Relink previous and next nodes to this new one
			prev.NextUUID[0] = rMP.uUID
			next.PreviousUUID[0] = rMP.uUID
			// Update prev
			jsonEntry, err := json.Marshal(prev)
			if err != nil {
				return errors.New("err")
			}
			err = db.Update(txnP, rP.uUID, jsonEntry, map[string]string{
				"knowledgeID": prev.KnowledgeUUID,
			})
			// Update next
			jsonEntry, err = json.Marshal(next)
			if err != nil {
				return errors.New("err")
			}
			_ = db.Update(txnN, rN.uUID, jsonEntry, map[string]string{
				"knowledgeID": next.KnowledgeUUID,
			})
		} else {
			// Only a next node -> error
			return errors.New("err")
		}
	} else {
		// No next nodes provided
		if len(process.PreviousUUID) <= 0 {
			// No previous nodes no next nodes -> main node (technically root node)
			isMainNode = true
			neighborless = true
		} else {
			// Previous nodes without next nodes -> check if previous node has next nodes
			// Get previous main node
			rP, txnP := db.Get(process.PreviousUUID[0])
			if txnP == nil {
				return errors.New("err")
			}
			defer txnP.Discard()
			prev := &Process{}
			err := json.Unmarshal(rP.Data, prev)
			if err != nil {
				return errors.New("err")
			}
			if len(prev.NextUUID) < 1 {
				// No nodes following the previous one -> main node
				isMainNode = true
			} else {
				// There are nodes following the previous one -> sub node
				isMainNode = false
			}
			// Update previous node if it did not contain the current node already
			if !slices.Contains(prev.NextUUID, rMP.uUID) {
				prev.NextUUID = append(prev.NextUUID, rMP.uUID)
				jsonEntry, err := json.Marshal(prev)
				if err != nil {
					return errors.New("err")
				}
				err = db.Update(txnP, rP.uUID, jsonEntry, map[string]string{
					"knowledgeID": prev.KnowledgeUUID,
				})
			}
		}
	}
	// Check row indices of neighboring nodes (if available)
	// We need to make sure the indices do not get too small
	var position int
	if process.RowIndex <= 0.0 {
		// Index below 0 -> Attach to the end
		position = 1
	} else if process.RowIndex < 1.0 {
		// Index between 0 and 1 -> Put in front but redistribute new index values starting from 20_000
		position = -1
	} else {
		// Index greater than 1 -> Put it where it belongs
		// We still redistribute row indices if the distance becomes too small
		position = 0
	}
	if !neighborless && isMainNode {
		// Check main path only
		var path ProcessPath
		var p *Process
		var ok bool
		var response *EntryResponse
		if len(process.PreviousUUID) > 0 {
			response, ok = db.Read(process.PreviousUUID[0])
		} else {
			response, ok = db.Read(process.NextUUID[0])
		}
		if !ok {
			return errors.New("err")
		}
		p = &Process{}
		err := json.Unmarshal(response.Data, p)
		if err != nil {
			fmt.Println(err)
			return errors.New("err")
		}
		path = ProcessPath{Processes: make([]*ProcessPathContainer, 0)}
		path = db.getPathOfProcess(p, response.uUID, path, false, -1)
		if position == -1 {
			// Node is the new root note
			process.RowIndex = 20_000.0
			// Redistribute row index values from 40k onwards
			v := 40_000.0
			var txSeg *badger.Txn
			for _, segment := range path.Processes {
				// Do not modify current process since we already did that
				if segment.Process.UUID == rMP.uUID {
					continue
				}
				segment.Process.RowIndex = v
				// Increment
				v += 20_000.0
				// Update
				jsonEntry, err := json.Marshal(segment.Process)
				if err != nil {
					continue
				}
				_, txSeg = db.Get(segment.Process.UUID)
				if txSeg == nil {
					continue
				}
				_ = db.Update(txSeg, segment.Process.UUID, jsonEntry, map[string]string{
					"knowledgeID": segment.Process.KnowledgeUUID,
				})
			}
		} else if position == 1 {
			// Attach node to the end
			lastProcess := path.Processes[len(path.Processes)-1].Process
			process.RowIndex = lastProcess.RowIndex + 20_000.0
		} else if position == 0 {
			// TODO: Check if row index and row index differences are ok
		}
	} else if !neighborless {
		// We need to check full path segment
		var path ProcessPath
		var p *Process
		var response *EntryResponse
		response, ok := db.Read(process.PreviousUUID[0])
		if !ok {
			return errors.New("err")
		}
		p = &Process{}
		err := json.Unmarshal(response.Data, p)
		if err != nil {
			fmt.Println(err)
			return errors.New("err")
		}
		path = ProcessPath{Processes: make([]*ProcessPathContainer, 0)}
		path = db.getPathOfProcess(p, response.uUID, path, true, 1)
		if position == -1 {
			// Node is the new sub root note
			process.RowIndex = 20_000.0
			// Redistribute row index values from 40k onwards
			v := 40_000.0
			for _, segment := range path.Processes[0].Children {
				// Do not modify current process since we already did that
				if segment.UUID == rMP.uUID {
					continue
				}
				segment.Process.RowIndex = v
				// Increment
				v += 20_000.0
				// Update
				jsonEntry, err := json.Marshal(segment.Process)
				if err != nil {
					continue
				}
				_, txSeg := db.Get(segment.UUID)
				if txSeg == nil {
					continue
				}
				_ = db.Update(txSeg, segment.UUID, jsonEntry, map[string]string{
					"knowledgeID": segment.Process.KnowledgeUUID,
				})
			}
		} else if position == 1 {
			// Attach node to the end
			if len(path.Processes[0].Children) > 0 {
				lastSegment := path.Processes[0].Children[len(path.Processes[0].Children)-1]
				process.RowIndex = lastSegment.RowIndex + 20_000.0
			} else {
				process.RowIndex = 20_000.0
			}
		} else if position == 0 {
			// TODO: Check if row index and row index differences are ok
		}
	} else {
		process.IsRootNode = true
		process.RowIndex = 20_000
	}
	return nil
}

func (db *GoDB) handleProcessEdit(
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		processID := chi.URLParam(r, "processID")
		if processID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, txn := db.Get(processID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		defer txn.Discard()
		process := &Process{}
		err := json.Unmarshal(response.Data, process)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, process.KnowledgeUUID, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve POST payload
		request := &ProcessModification{}
		if err := render.Bind(r, request); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if request.Field == "row" {
			process.RowIndex = request.RowIndex
			// Check if rows need to be recalculated
			err = db.rearrangeProcesses(process, response)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else if request.Field == "link" {
			// Exit with an error if no links are provided
			if request.FromUUID == "" && request.ToUUID == "" {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			// Exit without an error if links did not change (maybe a mistake was made)
			if request.FromUUID == process.PreviousUUID[0] && request.ToUUID == process.NextUUID[0] {
				return
			}
			process.PreviousUUID[0] = request.FromUUID
			process.NextUUID[0] = request.ToUUID
			process.RowIndex = request.RowIndex
			// Check if rows need to be recalculated
			err = db.rearrangeProcesses(process, response)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		}
		// Update
		jsonEntry, err := json.Marshal(process)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(txn, processID, jsonEntry, map[string]string{
			"knowledgeID": process.KnowledgeUUID,
		})
	}
}

func (db *GoDB) handleProcessGetPath(
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		processID := chi.URLParam(r, "processID")
		if processID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Read(processID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		process := &Process{}
		err := json.Unmarshal(response.Data, process)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check read right
		knowledgeAccess, _ := CheckKnowledgeAccess(
			user, process.KnowledgeUUID, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Retrieve all Process nodes connected to this Process
		path := db.getPathOfProcess(
			process, processID, ProcessPath{Processes: make([]*ProcessPathContainer, 0)}, true, -1)
		render.JSON(w, r, path)
	}
}

func (db *GoDB) getPathOfProcess(
	process *Process, uUID string, path ProcessPath, children bool, depth int,
) ProcessPath {
	pathSegment := &ProcessPathContainer{
		Process: &ProcessContainer{
			Process:   process,
			Analytics: &Analytics{},
			UUID:      uUID},
		Children: make([]*ProcessContainer, 0),
	}
	if len(process.NextUUID) < 1 {
		// Exit if there are no next nodes available (anymore)
		path.Processes = append(path.Processes, pathSegment)
		if len(path.Processes) > 1 {
			sort.SliceStable(
				path.Processes, func(i, j int) bool {
					return path.Processes[i].Process.RowIndex < path.Processes[j].Process.RowIndex
				},
			)
		}
		return path
	}
	if children && len(process.NextUUID) > 1 {
		for i, nextUUID := range process.NextUUID {
			// We will skip the first one since it will be the next main node
			if i > 0 {
				response, ok := db.Read(nextUUID)
				if !ok {
					continue
				}
				p := &Process{}
				err := json.Unmarshal(response.Data, p)
				if err != nil {
					continue
				}
				pathSegment.Children = append(pathSegment.Children, &ProcessContainer{
					Process:   p,
					Analytics: &Analytics{},
					UUID:      nextUUID,
				})
			}
		}
		// Sort children by row index
		if len(pathSegment.Children) > 1 {
			sort.SliceStable(
				pathSegment.Children, func(i, j int) bool {
					return pathSegment.Children[i].RowIndex < pathSegment.Children[j].RowIndex
				},
			)
		}
	}
	// Append current segment
	path.Processes = append(path.Processes, pathSegment)
	// Continue over the next node's children recursively
	response, ok := db.Read(process.NextUUID[0])
	if !ok {
		if len(path.Processes) > 1 {
			sort.SliceStable(
				path.Processes, func(i, j int) bool {
					return path.Processes[i].Process.RowIndex < path.Processes[j].Process.RowIndex
				},
			)
		}
		return path
	}
	nextNode := &Process{}
	err := json.Unmarshal(response.Data, nextNode)
	if err != nil {
		if len(path.Processes) > 1 {
			sort.SliceStable(
				path.Processes, func(i, j int) bool {
					return path.Processes[i].Process.RowIndex < path.Processes[j].Process.RowIndex
				},
			)
		}
		return path
	}
	if depth != -1 {
		depth -= 1
		if depth == 0 {
			if len(path.Processes) > 1 {
				sort.SliceStable(
					path.Processes, func(i, j int) bool {
						return path.Processes[i].Process.RowIndex < path.Processes[j].Process.RowIndex
					},
				)
			}
			return path
		}
	}
	return db.getPathOfProcess(nextNode, process.NextUUID[0], path, children, depth)
}

func (a *ProcessModification) Bind(_ *http.Request) error {
	if a.Field == "" {
		return errors.New("missing field")
	}
	return nil
}

func (db *GoDB) handleProcessDelete(
	chatGroupDB, chatMemberDB, notificationDB, knowledgeDB *GoDB, connector *Connector,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := r.Context().Value("user").(*User)
		if user == nil {
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}
		processID := chi.URLParam(r, "processID")
		if processID == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		response, ok := db.Read(processID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		process := &Process{}
		err := json.Unmarshal(response.Data, process)
		if err != nil {
			fmt.Println(err)
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, process.KnowledgeUUID, chatGroupDB, chatMemberDB, knowledgeDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Do we need to relink process nodes?
		if len(process.NextUUID) > 0 {
			// Is there a node before this one?
			if len(process.PreviousUUID) > 0 {
				// Attach next node to this node's previous node to close the gap
				// 1. [PREV] <-> CURRENT <-> [NEXT]
				// 2. [PREV]                 [NEXT]
				// 3. [PREV] <-> [NEXT]
				rPrev, tPRev := db.Get(process.PreviousUUID[0])
				if tPRev == nil {
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				defer tPRev.Discard()
				prev := &Process{}
				err = json.Unmarshal(rPrev.Data, prev)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				rNext, tNext := db.Get(process.NextUUID[0])
				if tNext == nil {
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				defer tNext.Discard()
				next := &Process{}
				err = json.Unmarshal(rNext.Data, next)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				// Connect the two process nodes
				prev.NextUUID[0] = rNext.uUID
				next.PreviousUUID[0] = rPrev.uUID
				// Commit changes (prev)
				jsonEntry, err := json.Marshal(prev)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(tPRev, rPrev.uUID, jsonEntry, map[string]string{
					"knowledgeID": prev.KnowledgeUUID,
				})
				// Commit changes (next)
				jsonEntry, err = json.Marshal(next)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(tNext, rNext.uUID, jsonEntry, map[string]string{
					"knowledgeID": next.KnowledgeUUID,
				})
			} else {
				// Only a next node available
				// Remove the reference to this current node
				rNext, tNext := db.Get(process.NextUUID[0])
				if tNext == nil {
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				defer tNext.Discard()
				next := &Process{}
				err = json.Unmarshal(rNext.Data, next)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				next.PreviousUUID[0] = ""
				// Commit changes (next)
				jsonEntry, err := json.Marshal(next)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(tNext, rNext.uUID, jsonEntry, map[string]string{
					"knowledgeID": next.KnowledgeUUID,
				})
			}
		} else {
			// Is there a node before this one?
			if len(process.PreviousUUID) > 0 {
				// Only a previous node available
				rPrev, tPrev := db.Get(process.PreviousUUID[0])
				if tPrev == nil {
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				defer tPrev.Discard()
				prev := &Process{}
				err = json.Unmarshal(rPrev.Data, prev)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				prev.NextUUID[0] = ""
				// Commit changes (Prev)
				jsonEntry, err := json.Marshal(prev)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(tPrev, rPrev.uUID, jsonEntry, map[string]string{
					"knowledgeID": prev.KnowledgeUUID,
				})
			}
		}
	}
}
