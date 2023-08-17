package main

import (
	"fmt"
	"github.com/go-chi/chi/v5"
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

var tokenAuth *jwtauth.JWTAuth

var cs chan bool

func StartServer(_cs chan bool, wg *sync.WaitGroup, config Config) {
	fmt.Println(":: INIT SERVER")
	cs = _cs
	// Initialize JWT Authenticator
	setupJWTAuth(config)
	// Are we using HTTPS or not?
	isSecure := checkHTTPS()
	// Create Router
	r := chi.NewRouter()
	// Routes
	setPublicRoutes(r)
	setProtectedRoutes(r)
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

func generateToken(user User) string {
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

func setPublicRoutes(r chi.Router) {
	r.Get("/sample", sampleMessage)
	vueJSWikiricEndpoint(r)
	// Users
	userDB := OpenUserDatabase()
	userDB.UserEndpoints(r, tokenAuth)
	// Chat Server
	CreateChatServer().WebsocketChatEndpoint(r, tokenAuth, userDB)

}

func setProtectedRoutes(r chi.Router) {
	r.Group(func(r chi.Router) {
		// Seek, verify and validate JWT tokens
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)
		// Protected routes
		r.Get("/jwt", func(w http.ResponseWriter, r *http.Request) {
			_, claims, _ := jwtauth.FromContext(r.Context())
			_, _ = w.Write([]byte(fmt.Sprintf("ID: %v, USR: %v", claims["u_uiid"], claims["u_name"])))
		})
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
