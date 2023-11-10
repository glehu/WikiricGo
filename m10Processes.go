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
	"slices"
	"sort"
	"strings"
	"time"
)

const ProcessDB = "m10"

type Process struct {
	Name                 string   `json:"t"`
	Description          string   `json:"desc"`
	Author               string   `json:"usr"`
	Categories           []string `json:"cats"`
	Keywords             string   `json:"keys"`
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
	UUID     string  `json:"uid"`
	Accuracy float64 `json:"accuracy"`
}

type ProcessPathContainer struct {
	Process  *ProcessContainer   `json:"process"`
	Children []*ProcessContainer `json:"children"`
}

type ProcessPath struct {
	Processes []*ProcessPathContainer `json:"path"`
}

type ProcessModification struct {
	Field    string  `json:"field"`
	NewValue string  `json:"new"`
	FromUUID string  `json:"fromId"`
	ToUUID   string  `json:"toId"`
	RowIndex float64 `json:"row"`
}

type ProcessQueryResponse struct {
	TimeSeconds float64             `json:"respTime"`
	Processes   []*ProcessContainer `json:"processes"`
}

func (db *GoDB) ProtectedProcessEndpoints(
	r chi.Router, tokenAuth *jwtauth.JWTAuth,
	mainDB *GoDB, connector *Connector,
) {
	r.Route("/process/private", func(r chi.Router) {
		// ############
		// ### POST ###
		// ############
		r.Post("/create", db.handleProcessCreate(mainDB, connector))
		r.Post("/edit/{processID}", db.handleProcessEdit(mainDB, connector))
		r.Post("/query/{knowledgeID}", db.handleProcessQuery(mainDB))
		// ###########
		// ### GET ###
		// ###########
		r.Get("/path/{processID}", db.handleProcessGetPath(mainDB, connector))
		r.Get("/delete/{processID}", db.handleProcessDelete(mainDB, connector))
	})
}

func (p *Process) Bind(_ *http.Request) error {
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
	err = db.Update(ProcessDB, txn, id, jsonEntry, map[string]string{
		"knowledgeID": p.KnowledgeUUID,
	})
	if err != nil {
		return err
	}
	return nil
}

func (db *GoDB) handleProcessCreate(
	mainDB *GoDB, connector *Connector,
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
			user, request.KnowledgeUUID, mainDB, r)
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
		uUID, err := db.Insert(ProcessDB, jsonEntry, map[string]string{
			"knowledgeID": request.KnowledgeUUID,
		})
		resp, ok := db.Read(ProcessDB, uUID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
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
		resp, txn := db.Get(ProcessDB, uUID)
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
			rP, txnP := db.Get(ProcessDB, process.PreviousUUID[0])
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
			rN, txnN := db.Get(ProcessDB, process.NextUUID[0])
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
			err = db.Update(ProcessDB, txnP, rP.uUID, jsonEntry, map[string]string{
				"knowledgeID": prev.KnowledgeUUID,
			})
			// Update next
			jsonEntry, err = json.Marshal(next)
			if err != nil {
				return errors.New("err")
			}
			_ = db.Update(ProcessDB, txnN, rN.uUID, jsonEntry, map[string]string{
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
			rP, txnP := db.Get(ProcessDB, process.PreviousUUID[0])
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
				err = db.Update(ProcessDB, txnP, rP.uUID, jsonEntry, map[string]string{
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
			response, ok = db.Read(ProcessDB, process.PreviousUUID[0])
		} else {
			response, ok = db.Read(ProcessDB, process.NextUUID[0])
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
				_, txSeg = db.Get(ProcessDB, segment.Process.UUID)
				if txSeg == nil {
					continue
				}
				_ = db.Update(ProcessDB, txSeg, segment.Process.UUID, jsonEntry, map[string]string{
					"knowledgeID": segment.Process.KnowledgeUUID,
				})
			}
		} else if position == 1 {
			// Attach task to the end of all other process nodes
			highestRow := 0.0
			for _, pEntry := range path.Processes {
				// Do not check process being edited here since we already did that
				if pEntry.Process.UUID == rMP.uUID {
					continue
				}
				if pEntry.Process.RowIndex > highestRow {
					highestRow = pEntry.Process.RowIndex
				}
			}
			process.RowIndex = highestRow + 20_000.0
		} else if position == 0 {
			// TODO: Check if row index and row index differences are ok
		}
	} else if !neighborless {
		// We need to check full path segment
		var path ProcessPath
		var p *Process
		var response *EntryResponse
		response, ok := db.Read(ProcessDB, process.PreviousUUID[0])
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
				_, txSeg := db.Get(ProcessDB, segment.UUID)
				if txSeg == nil {
					continue
				}
				_ = db.Update(ProcessDB, txSeg, segment.UUID, jsonEntry, map[string]string{
					"knowledgeID": segment.Process.KnowledgeUUID,
				})
			}
		} else if position == 1 {
			// Attach node to the end
			if len(path.Processes[0].Children) > 0 {
				highestRow := 0.0
				for _, pEntry := range path.Processes[0].Children {
					// Do not check process being edited here since we already did that
					if pEntry.UUID == rMP.uUID {
						continue
					}
					if pEntry.RowIndex > highestRow {
						highestRow = pEntry.RowIndex
					}
				}
				process.RowIndex = highestRow + 20_000.0
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

func (db *GoDB) handleProcessEdit(mainDB *GoDB, connector *Connector,
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
		response, ok := db.Read(ProcessDB, processID)
		if !ok {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}
		process := &Process{}
		err := json.Unmarshal(response.Data, process)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		// Check write right
		_, knowledgeAccess := CheckKnowledgeAccess(
			user, process.KnowledgeUUID, mainDB, r)
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
			if len(process.PreviousUUID) > 0 && request.FromUUID == process.PreviousUUID[0] &&
				len(process.NextUUID) > 0 && request.ToUUID == process.NextUUID[0] {
				return
			}
			// Update links
			if request.FromUUID != "" {
				// Check if targeted previous node has a next node
				// If it doesn't we will check if the current process is supposed to be a sub node
				// If the current process is a sub node, we will create an empty process to be the next main node
				respPrev, txnPrev := db.Get(ProcessDB, request.FromUUID)
				if txnPrev == nil {
					http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
					return
				}
				pPrev := &Process{}
				err := json.Unmarshal(respPrev.Data, pPrev)
				if err != nil {
					txnPrev.Discard()
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				if len(pPrev.NextUUID) < 1 {
					mode := r.URL.Query().Get("mode")
					if mode == "sub" {
						// Create an empty process to be the next main node, enabling the current process to be a sub node
						jsonEntry, err := json.Marshal(&Process{
							Author:        process.Author,
							Categories:    make([]string, 0),
							PreviousUUID:  make([]string, 0),
							NextUUID:      make([]string, 0),
							TimeCreated:   TimeNowIsoString(),
							IsPublic:      process.IsPublic,
							KnowledgeUUID: process.KnowledgeUUID,
							IsRootNode:    false,
							Collaborators: make([]string, 0),
							RowIndex:      pPrev.RowIndex + 20_000,
						})
						if err != nil {
							http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
							return
						}
						uUID, err := db.Insert(ProcessDB, jsonEntry, map[string]string{
							"knowledgeID": process.KnowledgeUUID,
						})
						pPrev.NextUUID = append(pPrev.NextUUID, uUID)
						jsonEntry, err = json.Marshal(pPrev)
						if err != nil {
							http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
							return
						}
						err = db.Update(ProcessDB, txnPrev, respPrev.uUID, jsonEntry, map[string]string{
							"knowledgeID": pPrev.KnowledgeUUID,
						})
					}
				}
				// Check if previous node needs to be dereferenced
				if len(process.PreviousUUID) > 0 {
					// Remove link in previous node since it changed now
					respPrev, txnPrev = db.Get(ProcessDB, process.PreviousUUID[0])
					if txnPrev == nil {
						http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
						return
					}
					defer txnPrev.Discard()
					pPrev = &Process{}
					err = json.Unmarshal(respPrev.Data, pPrev)
					if err != nil {
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					didChange := false
					for ix, id := range pPrev.NextUUID {
						if id == processID {
							if ix == 0 {
								// We're about to remove a main node, so check if the next main node can be connected
								if len(process.NextUUID) > 0 {
									// We have a main node to be used as a replacement
									pPrev.NextUUID[0] = process.NextUUID[0]
									didChange = true
									break
								} else {
									// Delete instead of replacing it
									pPrev.NextUUID = append(pPrev.NextUUID[:ix], pPrev.NextUUID[ix+1:]...)
								}
							} else {
								// We're safe! :D No main node to be removed
								pPrev.NextUUID = append(pPrev.NextUUID[:ix], pPrev.NextUUID[ix+1:]...)
								didChange = true
								break
							}
						}
					}
					if didChange {
						jsonEntry, err := json.Marshal(pPrev)
						if err != nil {
							http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
							return
						}
						err = db.Update(ProcessDB, txnPrev, respPrev.uUID, jsonEntry, map[string]string{
							"knowledgeID": pPrev.KnowledgeUUID,
						})
					} else {
						txnPrev.Discard()
					}
					// Update new link
					process.PreviousUUID[0] = request.FromUUID
				} else {
					process.PreviousUUID = append(process.PreviousUUID, request.FromUUID)
				}
			} else {
				if len(process.PreviousUUID) > 0 {
					process.PreviousUUID[0] = ""
				}
			}
			if request.ToUUID != "" {
				if len(process.NextUUID) > 0 {
					// Remove link in next node since it changed now
					respNext, txnNext := db.Get(ProcessDB, process.NextUUID[0])
					if txnNext == nil {
						http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
						return
					}
					defer txnNext.Discard()
					pNext := &Process{}
					err = json.Unmarshal(respNext.Data, pNext)
					if err != nil {
						http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
						return
					}
					didChange := false
					for ix, id := range pNext.PreviousUUID {
						if id == processID {
							if ix == 0 {
								// We're about to remove a main node, so check if the next main node can be connected
								if len(process.PreviousUUID) > 0 {
									// We have a main node to be used as a replacement
									pNext.PreviousUUID[0] = process.PreviousUUID[0]
									didChange = true
									break
								} else {
									// Delete instead of replacing it
									pNext.PreviousUUID = append(pNext.PreviousUUID[:ix], pNext.PreviousUUID[ix+1:]...)
								}
							} else {
								// We're safe! :D No main node to be removed
								pNext.PreviousUUID = append(pNext.PreviousUUID[:ix], pNext.PreviousUUID[ix+1:]...)
								didChange = true
								break
							}
						}
					}
					if didChange {
						jsonEntry, err := json.Marshal(pNext)
						if err != nil {
							http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
							return
						}
						err = db.Update(ProcessDB, txnNext, respNext.uUID, jsonEntry, map[string]string{
							"knowledgeID": pNext.KnowledgeUUID,
						})
					} else {
						txnNext.Discard()
					}
					// Update new link
					process.NextUUID[0] = request.ToUUID
				} else {
					process.NextUUID = append(process.NextUUID, request.ToUUID)
				}
			} else {
				if len(process.NextUUID) > 0 {
					process.NextUUID[0] = ""
				}
			}
			// Update row index
			process.RowIndex = request.RowIndex
			// Check if rows need to be recalculated
			err = db.rearrangeProcesses(process, response)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		} else if request.Field == "title" {
			process.Name = request.NewValue
		} else if request.Field == "desc" {
			process.Description = request.NewValue
		}
		// Update
		_, txn := db.Get(ProcessDB, processID)
		if txn == nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		jsonEntry, err := json.Marshal(process)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		err = db.Update(ProcessDB, txn, processID, jsonEntry, map[string]string{
			"knowledgeID": process.KnowledgeUUID,
		})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}
}

func (db *GoDB) handleProcessGetPath(
	mainDB *GoDB, connector *Connector,
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
		response, ok := db.Read(ProcessDB, processID)
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
			user, process.KnowledgeUUID, mainDB, r)
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
				response, ok := db.Read(ProcessDB, nextUUID)
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
	response, ok := db.Read(ProcessDB, process.NextUUID[0])
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

func (db *GoDB) handleProcessDelete(mainDB *GoDB, connector *Connector) http.HandlerFunc {
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
		response, ok := db.Read(ProcessDB, processID)
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
			user, process.KnowledgeUUID, mainDB, r)
		if !knowledgeAccess {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		// Delete process node
		err = db.Delete(ProcessDB, processID, []string{"knowledgeID"})
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
				rPrev, tPRev := db.Get(ProcessDB, process.PreviousUUID[0])
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
				rNext, tNext := db.Get(ProcessDB, process.NextUUID[0])
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
				err = db.Update(ProcessDB, tPRev, rPrev.uUID, jsonEntry, map[string]string{
					"knowledgeID": prev.KnowledgeUUID,
				})
				// Commit changes (next)
				jsonEntry, err = json.Marshal(next)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(ProcessDB, tNext, rNext.uUID, jsonEntry, map[string]string{
					"knowledgeID": next.KnowledgeUUID,
				})
			} else {
				// Only a next node available
				// Remove the reference to this current node
				rNext, tNext := db.Get(ProcessDB, process.NextUUID[0])
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
				err = db.Update(ProcessDB, tNext, rNext.uUID, jsonEntry, map[string]string{
					"knowledgeID": next.KnowledgeUUID,
				})
			}
		} else {
			// Is there a node before this one?
			if len(process.PreviousUUID) > 0 {
				// Only a previous node available
				rPrev, tPrev := db.Get(ProcessDB, process.PreviousUUID[0])
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
				for ix, id := range prev.NextUUID {
					if id == processID {
						if ix == 0 {
							// We're about to remove a main node, so check if the next main node can be connected
							if len(process.NextUUID) > 0 {
								// We have a main node to be used as a replacement
								prev.NextUUID[0] = process.NextUUID[0]
								break
							} else {
								// Delete instead of replacing it
								prev.NextUUID = append(prev.NextUUID[:ix], prev.NextUUID[ix+1:]...)
							}
						} else {
							// We're safe! :D No main node to be removed
							prev.NextUUID = append(prev.NextUUID[:ix], prev.NextUUID[ix+1:]...)
							break
						}
					}
				}
				// Commit changes (Prev)
				jsonEntry, err := json.Marshal(prev)
				if err != nil {
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				err = db.Update(ProcessDB, tPrev, rPrev.uUID, jsonEntry, map[string]string{
					"knowledgeID": prev.KnowledgeUUID,
				})
			}
		}
	}
}

func (db *GoDB) handleProcessQuery(mainDB *GoDB) http.HandlerFunc {
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
		// Retrieve all processes
		resp, err := db.Select(ProcessDB, map[string]string{
			"knowledgeID": knowledgeID,
		}, nil)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		queryResponse := &ProcessQueryResponse{
			TimeSeconds: 0,
			Processes:   make([]*ProcessContainer, 0),
		}
		response := <-resp
		if len(response) < 1 {
			render.JSON(w, r, queryResponse)
			return
		}
		// Turn query text into a full regex pattern
		words, p := GetRegexQuery(request.Query)
		var process *Process
		var analytics *Analytics
		var points int64
		var accuracy float64
		b := false
		for _, entry := range response {
			process = &Process{}
			err = json.Unmarshal(entry.Data, process)
			if err != nil {
				continue
			}
			// Flip boolean on each iteration
			b = !b
			accuracy, points = GetProcessQueryPoints(process, request, p, words, b)
			if points <= 0.0 {
				continue
			}
			// Load analytics if available
			analytics = &Analytics{}
			if process.AnalyticsUUID != "" {
				anaBytes, okAna := db.Read(AnaDB, process.AnalyticsUUID)
				if okAna {
					err = json.Unmarshal(anaBytes.Data, analytics)
					if err != nil {
						analytics = &Analytics{}
					}
				}
			}
			// Truncate wisdom description
			if process.Description != "" {
				process.Description = EllipticalTruncate(process.Description, 200)
			}
			queryResponse.Processes = append(queryResponse.Processes, &ProcessContainer{
				UUID:      entry.uUID,
				Process:   process,
				Analytics: analytics,
				Accuracy:  accuracy,
			})
		}
		// Sort entries by accuracy
		if len(queryResponse.Processes) > 1 {
			sort.SliceStable(
				queryResponse.Processes, func(i, j int) bool {
					return queryResponse.Processes[i].Accuracy > queryResponse.Processes[j].Accuracy
				},
			)
		}
		duration := time.Since(timeStart)
		queryResponse.TimeSeconds = duration.Seconds()
		render.JSON(w, r, queryResponse)
	}
}

func GetProcessQueryPoints(
	process *Process, query *WisdomQuery, p *regexp.Regexp, words map[string]*QueryWord, b bool,
) (float64, int64) {
	// Get all matches in selected fields
	var mUser, mName, mDesc, mKeys []string
	if query.Fields == "" || strings.Contains(query.Fields, "usr") {
		mUser = p.FindAllString(process.Author, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "title") {
		mName = p.FindAllString(process.Name, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "desc") {
		mDesc = p.FindAllString(process.Description, -1)
	}
	if query.Fields == "" || strings.Contains(query.Fields, "keys") {
		mKeys = p.FindAllString(process.Keywords, -1)
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
	// How many words were matched?
	for _, word := range words {
		if word.B == b {
			points += word.Points
		}
	}
	accuracy = float64(points) / float64(pointsMax)
	return accuracy, points
}
