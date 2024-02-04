package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"firebase.google.com/go/messaging"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/go-chi/httprate"
	"github.com/go-chi/jwtauth/v5"
	"github.com/gofrs/uuid"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const REALM = "Access to the '/' path"

var tokenAuth *jwtauth.JWTAuth

var cs chan bool

func StartServer(_cs chan bool, wg *sync.WaitGroup, config Config,
	dbList *Databases, chatServer *ChatServer, connector *Connector,
	fcmClient *messaging.Client, emailClient *EmailClient,
) {
	startTime := time.Now()
	fmt.Println(":: INIT SERVER")
	cs = _cs
	// Initialize JWT Authenticator
	setupJWTAuth(config)
	// Are we using HTTPS or not?
	isSecure := checkHTTPS()
	// Create Router (with rate limit 100r/10s/endpoint)
	r := chi.NewRouter()
	r.Use(
		httprate.Limit(
			100,
			10*time.Second,
			httprate.WithKeyFuncs(httprate.KeyByIP, httprate.KeyByEndpoint),
		),
	)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS", "HEAD"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}))
	// Debug
	callCounter := &atomic.Int64{}
	// Pagination Middleware
	r.Use(PaginationMiddleware())
	r.Use(CallCounterMiddleware(callCounter))
	// Routes -> Public
	setPublicRoutes(r, dbList, chatServer, connector, callCounter, startTime, fcmClient, emailClient)
	// Routes -> Basic Auth
	setBasicProtectedRoutes(r, dbList.Map["main"])
	// Routes -> JWT Bearer Auth
	setJWTProtectedRoutes(r, dbList, chatServer, connector)
	// PWA (Progressive Web App)
	vueJSWikiricEndpoint(r)
	// Shutdown URL with random access token
	shutdownURL, err := uuid.NewV4()
	if err != nil {
		log.Fatal("FATAL ERROR GENERATING SHUTDOWN URL TOKEN")
	}
	setShutdownURL(r, shutdownURL.String())
	// Start Server
	go func() {
		var err error
		if !isSecure {
			url := fmt.Sprintf("%s:%s", config.Host, config.Port)
			fmt.Println(":: SERVE HTTP ", url)
			err = http.ListenAndServe(url, r)
		} else {
			workDir, _ := os.Getwd()
			pathFullchain := filepath.Join(workDir, "fullchain.pem")
			pathPrivateKey := filepath.Join(workDir, "privkey.pem")
			url := fmt.Sprintf("%s:%s", config.Host, config.PortTLS)
			fmt.Println(":: SERVE HTTPS ", url)
			err = http.ListenAndServeTLS(url,
				pathFullchain, pathPrivateKey, r)
		}
		if err != nil {
			fmt.Println(":: SERVER ERROR", err)
			wg.Done()
			return
		}
	}()
	// Wait for underlying process to end
	if <-cs {
		fmt.Println(":: STOP SERVE")
		wg.Done()
	}
}

func setupJWTAuth(config Config) {
	tokenAuth = jwtauth.New("HS256", []byte(config.JwtSecret), nil)
	generateDebugToken()
}

func generateToken(user *User) (string, int64) {
	claims := map[string]interface{}{
		"u_name": user.Username,
	}
	expiresIn := 1 * time.Hour
	jwtauth.SetExpiryIn(claims, expiresIn)
	_, tokenString, err := tokenAuth.Encode(claims)
	if err != nil {
		log.Panicf("err generating jwt token for %s", user.Username)
	}
	return tokenString, expiresIn.Milliseconds()
}

func generateDebugToken() {
	claims := map[string]interface{}{
		"u_name": "debug_usr",
	}
	jwtauth.SetExpiryIn(claims, 1*time.Hour)
	_, tokenString, _ := tokenAuth.Encode(claims)
	decoded, _ := tokenAuth.Decode(tokenString)
	userName, _ := decoded.Get("_name")
	fmt.Printf(
		"\nDEBUG: JWT (u_name=%s) Expires @ %s \n%s\n\n",
		userName, time.Now().Add(time.Minute*30), tokenString,
	)
}

func checkHTTPS() bool {
	workDir, _ := os.Getwd()
	pathFullchain := filepath.Join(workDir, "fullchain.pem")
	pathPrivateKey := filepath.Join(workDir, "privkey.pem")
	if !FileExists(pathFullchain) {
		return false
	}
	if !FileExists(pathPrivateKey) {
		return false
	}
	return true
}

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func setShutdownURL(r chi.Router, url string) {
	r.Get(fmt.Sprintf("/shutdown/%s", url), handleShutdown)
}

func setPublicRoutes(r chi.Router, dbList *Databases,
	chatServer *ChatServer, connector *Connector, callCounter *atomic.Int64, startTime time.Time,
	fcmClient *messaging.Client, emailClient *EmailClient,
) {
	r.Get("/sample", sampleMessage)
	r.Get("/debug", handleDebugEndpoint(dbList, chatServer, connector, callCounter, startTime))
	// *** MAIN DATABASE ***                                                                                              *** MAIN
	// #### Users
	dbList.Map["main"].PublicUserEndpoints(r, tokenAuth, dbList.Map["rapid"])
	// #### Connector + Chat (WS Servers)
	connector.PublicConnectorEndpoint(r, tokenAuth, dbList)
	chatServer.PublicChatEndpoint(r, tokenAuth, dbList, connector, fcmClient)
	// #### Stores
	dbList.Map["main"].PublicStoreEndpoints(r, tokenAuth, dbList.Map["rapid"], connector, emailClient)
	// #### Mockingbird
	dbList.Map["main"].PublicMockingbirdEndpoints(r, tokenAuth, dbList.Map["rapid"], connector)
	// *** RAPID DATABASE ***                                                                                             *** RAPID
	// #### Files
	dbList.Map["rapid"].PublicFileEndpoints(r, tokenAuth)
	// #### Items
	dbList.Map["rapid"].PublicItemsEndpoints(r, tokenAuth, dbList.Map["main"])
}

func setBasicProtectedRoutes(r chi.Router, mainDB *GoDB) {
	r.Group(
		func(r chi.Router) {
			r.Use(BasicAuth(mainDB))
			// Debug/Testing Route
			r.Get(
				"/basic", func(w http.ResponseWriter, r *http.Request) {
					user := r.Context().Value("user").(*User)
					_, _ = w.Write([]byte(fmt.Sprintf("USR: %v", user.Username)))
				},
			)
			// Protected routes
			// #### Users
			mainDB.BasicProtectedUserEndpoints(r, tokenAuth)
		},
	)
}

func setJWTProtectedRoutes(
	r chi.Router, dbList *Databases, chatServer *ChatServer, connector *Connector,
) {
	r.Group(
		func(r chi.Router) {
			// Seek, verify and validate JWT tokens
			r.Use(jwtauth.Verifier(tokenAuth))
			r.Use(jwtauth.Authenticator)
			r.Use(BearerAuth(dbList.Map["main"]))
			// Debug/Testing Route
			r.Get(
				"/jwt", func(w http.ResponseWriter, r *http.Request) {
					_, claims, _ := jwtauth.FromContext(r.Context())
					_, _ = w.Write([]byte(fmt.Sprintf("ID: %v, USR: %v", claims["u_uiid"], claims["u_name"])))
				},
			)
			// Protected routes
			// *** MAIN DATABASE ***                                                                                          *** MAIN
			// #### Users
			dbList.Map["main"].ProtectedUserEndpoints(r, tokenAuth, dbList.Map["rapid"], connector)
			// #### Chat Groups
			dbList.Map["main"].ProtectedChatGroupEndpoints(r, tokenAuth, dbList.Map["rapid"], chatServer)
			// #### Knowledge
			dbList.Map["main"].ProtectedKnowledgeEndpoints(r, tokenAuth, dbList.Map["rapid"], chatServer)
			// #### Stores
			dbList.Map["main"].ProtectedStoreEndpoints(r, tokenAuth, dbList.Map["rapid"], connector)
			// #### Mockingbird
			dbList.Map["main"].ProtectedMockingbirdEndpoints(r, tokenAuth, dbList.Map["rapid"], connector)
			// *** RAPID DATABASE ***                                                                                         *** RAPID
			// #### Chat Messages
			dbList.Map["rapid"].ProtectedChatMessagesEndpoints(r, tokenAuth, chatServer, dbList.Map["main"])
			// #### Files
			dbList.Map["rapid"].ProtectedFileEndpoints(r, tokenAuth, dbList.Map["main"])
			// #### Notifications
			dbList.Map["rapid"].ProtectedNotificationEndpoints(r, tokenAuth)
			// #### Wisdom
			dbList.Map["rapid"].ProtectedWisdomEndpoints(r, tokenAuth, dbList.Map["main"], connector)
			// #### Processes
			dbList.Map["rapid"].ProtectedProcessEndpoints(r, tokenAuth, dbList.Map["main"], connector)
			// #### Periodic Actions
			dbList.Map["rapid"].ProtectedPeriodicActionsEndpoints(r, tokenAuth, dbList.Map["main"], connector)
			// #### Items
			dbList.Map["rapid"].ProtectedItemEndpoints(r, tokenAuth, dbList.Map["main"])
			// #### Orders
			dbList.Map["rapid"].ProtectedOrdersEndpoints(r, tokenAuth, dbList.Map["main"], connector)
			// #### Sandbox
			dbList.Map["rapid"].ProtectedSandboxEndpoints(r, tokenAuth, connector)
		},
	)
}

func handleShutdown(w http.ResponseWriter, req *http.Request) {
	fmt.Println(":: WARNING: SERVER SHUTDOWN URL REQUESTED")
	_, _ = w.Write([]byte("Server Shutdown"))
	cs <- true
}

func sampleMessage(w http.ResponseWriter, req *http.Request) {
	// Return message
	content := []byte("Sample Page Text")
	_, err := w.Write(content)
	if err != nil {
		fmt.Println("Could not respond to client on default page!", err)
	}
}

// vueJSWikiricEndpoint serves the wikiric Vue.js PWA website
func vueJSWikiricEndpoint(r chi.Router) {
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		workDir, _ := os.Getwd()
		filesDir := filepath.Join(workDir, "vue", "dist")
		if _, err := os.Stat(filesDir + r.URL.Path); errors.Is(err, os.ErrNotExist) {
			http.ServeFile(w, r, filepath.Join(filesDir, "index.html"))
		} else {
			http.ServeFile(w, r, filesDir+r.URL.Path)
		}
	})
}

func BasicAuth(mainDB *GoDB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				// Retrieve user credentials
				user, pass, ok := r.BasicAuth()
				if !ok {
					basicAuthFailed(w)
					return
				}
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
					basicAuthFailed(w)
					return
				}
				response := <-resp
				if len(response) < 1 {
					fmt.Printf("LOGIN for %s failed: user does not exist\n", user)
					basicAuthFailed(w)
					return
				}
				userFromDB := &User{}
				err = json.Unmarshal(response[0].Data, userFromDB)
				if err != nil {
					basicAuthFailed(w)
					return
				}
				// Retrieve hashed password from db user
				credPass := userFromDB.PassHash
				// Hash password from request
				h := sha256.New()
				h.Write([]byte(pass))
				userPass := fmt.Sprintf("%x", h.Sum(nil))
				// Compare both passwords
				if subtle.ConstantTimeCompare([]byte(userPass), []byte(credPass)) != 1 {
					fmt.Printf("LOGIN for %s failed: password does not match\n", user)
					basicAuthFailed(w)
					return
				}
				// Set user to context to be used for next steps after this middleware
				ctx := context.WithValue(r.Context(), "user", userFromDB)
				next.ServeHTTP(w, r.WithContext(ctx))
			},
		)
	}
}

func basicAuthFailed(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, REALM))
	w.WriteHeader(http.StatusUnauthorized)
}

func BearerAuth(mainDB *GoDB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				// Retrieve user credentials
				// Get client user
				_, claims, _ := jwtauth.FromContext(r.Context())
				username := claims["u_name"].(string)
				resp, err := mainDB.Select(UserDB,
					map[string]string{
						"usr": FIndex(username),
					}, nil,
				)
				if err != nil {
					fmt.Println(err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				response := <-resp
				if len(response) < 1 {
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
				userFromDB := &User{}
				err = json.Unmarshal(response[0].Data, userFromDB)
				if err != nil {
					fmt.Println(err)
					http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
					return
				}
				// Set user to context to be used for next steps after this middleware
				ctx := context.WithValue(r.Context(), "user", userFromDB)
				ctx = context.WithValue(ctx, "userID", response[0].uUID)
				next.ServeHTTP(w, r.WithContext(ctx))
			},
		)
	}
}

func PaginationMiddleware() func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				maxResultsTmp := r.URL.Query().Get("results")
				pageTmp := r.URL.Query().Get("page")
				skipTmp := r.URL.Query().Get("skip")
				// Check maxResults and page (page only if maxResults is present)
				var maxResults int64
				var page int64
				var err error
				if maxResultsTmp != "" {
					maxResults, err = strconv.ParseInt(maxResultsTmp, 10, 64)
					if err != nil {
						// no max results, no page
						maxResults = -1
						page = 0
					} else {
						// Sanitize
						if maxResults < -1 {
							maxResults = -1
						}
						// maxResults is present so page can be checked now
						if pageTmp != "" {
							page, err = strconv.ParseInt(pageTmp, 10, 64)
							if err != nil {
								page = 0
							} else {
								// Sanitize
								if page < 1 {
									page = 0
								}
							}
						} else {
							page = 0
						}
					}
				} else {
					// no max results, no page
					maxResults = -1
					page = 0
				}
				// Check for entries to be skipped
				var skip int64
				if skipTmp != "" {
					skip, err = strconv.ParseInt(skipTmp, 10, 64)
					if err != nil {
						skip = 0
					} else {
						// Sanitize
						if skip < 0 {
							skip = 0
						}
					}
				} else {
					skip = 0
				}
				options := &SelectOptions{
					MaxResults: maxResults,
					Page:       page,
					Skip:       skip,
				}
				// Set pagination options to context to be used for next steps after this middleware
				ctx := context.WithValue(r.Context(), "pagination", options)
				next.ServeHTTP(w, r.WithContext(ctx))
			},
		)
	}
}

func CallCounterMiddleware(c *atomic.Int64) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(
			func(w http.ResponseWriter, r *http.Request) {
				go func() {
					c.Add(1)
				}()
				next.ServeHTTP(w, r)
			})
	}
}

func handleDebugEndpoint(
	dbList *Databases, cs *ChatServer, c *Connector, callCounter *atomic.Int64, startTime time.Time,
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sb := &strings.Builder{}
		sb.WriteString("*** *** *** *** *** *** *** ***\n")
		sb.WriteString("*** WIKIRIC  BACKEND  DEBUG ***\n")
		sb.WriteString("*** *** *** *** *** *** *** ***\n")
		// Get all open chat sessions + connections
		chatSessions := 0
		chatUserSessions := 0
		cs.ChatGroups.Reverse(
			func(key string, value map[string]*Session) bool {
				chatSessions += 1
				chatUserSessions += len(value)
				return true
			},
		)
		sb.WriteString("\n[ CHAT ]\n")
		sb.WriteString(fmt.Sprintf("Chat Sessions: %d\n", chatSessions))
		sb.WriteString(fmt.Sprintf("User Sessions: %d\n", chatUserSessions))
		// Get all connector sessions
		sb.WriteString("\n[ CONNECTOR ]\n")
		sb.WriteString(fmt.Sprintf("User Sessions: %d\n", c.Sessions.Len()))
		// Current API call count
		sb.WriteString("\n[ HTTP ]\n")
		sb.WriteString(fmt.Sprintf("Request Count: %d\n", callCounter.Load()))
		// Sys
		sb.WriteString("\n[ SYSTEM ]\n")
		lastReboot := startTime.Format(time.RFC3339)
		lastReboot = strings.Replace(lastReboot, "T", " ", 1)
		sb.WriteString(fmt.Sprintf("Last Reboot:   %s\n", lastReboot))
		timeSince := time.Since(startTime)
		if timeSince.Hours() < 1 {
			sb.WriteString(fmt.Sprintf("Uptime Mins:   %.2f\n", timeSince.Minutes()))
		} else {
			sb.WriteString(fmt.Sprintf("Uptime Hours:  %.2f\n", timeSince.Hours()))
		}
		// DB
		sb.WriteString("\n[ DATABASES ]\n")
		sb.WriteString("LSM  = (Indices) Log-Structured-Merge-Tree\n")
		sb.WriteString("VLOG = (Entries) Value-Log\n\n")
		var lsm, vlog int64
		var lsmF, vlogF float64
		for key, value := range dbList.Map {
			lsm, vlog = value.db.Size()
			lsmF = float64(lsm)
			vlogF = float64(vlog)
			lsmF = lsmF / 1_000_000
			vlogF = vlogF / 1_000_000
			sb.WriteString(fmt.Sprintf("DB <%s>\n\t\tLSM  %f MB\n\t\tVLOG %f MB\n", key, lsmF, vlogF))
		}
		// Return to client
		_, _ = w.Write([]byte(sb.String()))
	}
}
