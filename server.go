package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/go-chi/jwtauth/v5"
	"github.com/gofrs/uuid"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const REALM = "Access to the '/' path"

var tokenAuth *jwtauth.JWTAuth

var cs chan bool

func StartServer(_cs chan bool, wg *sync.WaitGroup, config Config) {
	fmt.Println(":: INIT SERVER")
	cs = _cs
	// Initialize JWT Authenticator
	setupJWTAuth(config)
	// Are we using HTTPS or not?
	isSecure := checkHTTPS()
	// Create Router (with rate limit 100r/10s/endpoint)
	r := chi.NewRouter()
	r.Use(httprate.Limit(
		100,
		10*time.Second,
		httprate.WithKeyFuncs(httprate.KeyByIP, httprate.KeyByEndpoint),
	))
	// Databases
	userDB := OpenUserDatabase()
	// Routes
	setPublicRoutes(r, userDB)
	setBasicProtectedRoutes(r, userDB)
	setJWTProtectedRoutes(r)
	// Shutdown URL
	setShutdownURL(r)
	// Start Server
	go func() {
		var err error
		if !isSecure {
			fmt.Println(":: SERVE HTTP 8080")
			err = http.ListenAndServe(":8080", r)
		} else {
			fmt.Println(":: SERVE HTTPS 443")
			workDir, _ := os.Getwd()
			pathFullchain := filepath.Join(workDir, "fullchain.pem")
			pathPrivateKey := filepath.Join(workDir, "privkey.pem")
			err = http.ListenAndServeTLS(":443", pathFullchain, pathPrivateKey, r)
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
	tokenAuth = jwtauth.New("HS256", []byte(config.jwtSecret), nil)
	generateDebugToken()
}

func generateToken(user *User) string {
	claims := map[string]interface{}{
		"u_uuid": user.UUID,
		"u_name": user.Username,
	}
	jwtauth.SetExpiryIn(claims, time.Minute*30)
	_, tokenString, err := tokenAuth.Encode(claims)
	if err != nil {
		log.Panicf("err generating jwt token for %s", user.UUID)
	}
	return tokenString
}

func generateDebugToken() {
	uuidDebug, _ := uuid.NewV7()
	claims := map[string]interface{}{
		"u_uuid": uuidDebug,
		"u_name": "debug_usr",
	}
	jwtauth.SetExpiryIn(claims, time.Minute*30)
	_, tokenString, _ := tokenAuth.Encode(claims)
	decoded, _ := tokenAuth.Decode(tokenString)
	userName, _ := decoded.Get("_name")
	fmt.Printf("\nDEBUG: JWT (u_name=%s) Expires @ %s \n%s\n\n",
		userName, time.Now().Add(time.Minute*30), tokenString)
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

func setShutdownURL(r chi.Router) {
	r.Get("/secret/shutdown", handleShutdown)
}

func setPublicRoutes(r chi.Router, userDB *GoDB) {
	r.Get("/sample", sampleMessage)
	vueJSWikiricEndpoint(r)
	// Users
	userDB.PublicUserEndpoints(r, tokenAuth)
	// Chat WS Server
	chatServer := CreateChatServer()
	chatServer.PublicChatEndpoint(r, tokenAuth, userDB)
}

func setBasicProtectedRoutes(r chi.Router, userDB *GoDB) {
	r.Group(func(r chi.Router) {
		r.Use(BasicAuth(userDB))
		// Debug/Testing Route
		r.Get("/basic", func(w http.ResponseWriter, r *http.Request) {
			user := r.Context().Value("user").(*User)
			_, _ = w.Write([]byte(fmt.Sprintf("ID: %v, USR: %v", user.UUID, user.Username)))
		})
		// Protected routes
		// #### Users
		userDB.ProtectedUserEndpoints(r, tokenAuth)
	})
}

func setJWTProtectedRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		// Seek, verify and validate JWT tokens
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)
		// Debug/Testing Route
		r.Get("/jwt", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			_, _ = w.Write([]byte(fmt.Sprintf("ID: %v, USR: %v", claims["u_uiid"], claims["u_name"])))
		})
		// Protected routes
		// #### Users
	})
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

// vueJSWikiricEndpoint serves the wikiric vueJS PWA website
func vueJSWikiricEndpoint(r chi.Router) {
	workDir, _ := os.Getwd()
	filesDir := http.Dir(filepath.Join(workDir, "vue", "dist"))
	FileServer(r, "/", filesDir)
}

// FileServer conveniently sets up a http.FileServer handler to serve
// static files from a http.FileSystem.
func FileServer(r chi.Router, path string, root http.FileSystem) {
	if strings.ContainsAny(path, "{}*") {
		panic("FileServer does not permit any URL parameters.")
	}
	if path != "/" && path[len(path)-1] != '/' {
		r.Get(path, http.RedirectHandler(path+"/", 301).ServeHTTP)
		path += "/"
	}
	path += "*"
	r.Get(path, func(w http.ResponseWriter, r *http.Request) {
		rctx := chi.RouteContext(r.Context())
		pathPrefix := strings.TrimSuffix(rctx.RoutePattern(), "/*")
		fs := http.StripPrefix(pathPrefix, http.FileServer(root))
		fs.ServeHTTP(w, r)
	})
}

func BasicAuth(userDB *GoDB) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Retrieve user credentials
			user, pass, ok := r.BasicAuth()
			if !ok {
				basicAuthFailed(w)
				return
			}
			// Check if user exists in the database then compare passwords
			resp, err := userDB.Select(map[string]string{
				"username": user,
			})
			if err != nil {
				basicAuthFailed(w)
				return
			}
			response := <-resp
			if len(response) < 1 {
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
				basicAuthFailed(w)
				return
			}
			// Set user to context to be used for next steps after this middleware
			ctx := context.WithValue(r.Context(), "user", userFromDB)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func basicAuthFailed(w http.ResponseWriter) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf(`Basic realm="%s"`, REALM))
	w.WriteHeader(http.StatusUnauthorized)
}
