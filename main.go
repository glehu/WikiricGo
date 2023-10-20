package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	firebase "firebase.google.com/go"
	"firebase.google.com/go/messaging"
	"google.golang.org/api/option"
)

type Config struct {
	JwtSecret string `json:"jwtSecret"`
	Host      string `json:"ip"`
	Port      string `json:"port"`
	PortTLS   string `json:"portTLS"`
	EmailFrom string `json:"smtpFrom"`
	EmailPass string `json:"smtpPass"`
	EmailHost string `json:"smtpHost"`
	EmailPort string `json:"smtpPort"`
	Docker    bool   `json:"docker"`
}

type Databases struct {
	Map map[string]*GoDB
}

func main() {
	// RUNTIME
	runtime.GOMAXPROCS(128)
	// Debug
	dbug()
	// Create wait group and done channels
	wg := sync.WaitGroup{}
	doneServer := make(chan bool)
	donePeriodic := make(chan bool)
	// Setup
	config, err := getConfig()
	if err != nil {
		fmt.Println(":: Could not retrieve config.json")
	} else {
		fmt.Println(":: config.json loaded")
	}

	// Docker related init here
	if config.Docker == true {
		fmt.Println("::Starting in Docker ENV")
		// TODO: User (Docker) ENV instated of config.json values (e.g. jwtSecret)
	}

	// Setup Databases
	dbList := &Databases{Map: map[string]*GoDB{}}
	dbList.Map["users"] = OpenUserDatabase()
	dbList.Map["chats"] = OpenChatGroupDatabase()
	dbList.Map["members"] = OpenChatMemberDatabase()
	dbList.Map["msg"] = OpenChatMessageDatabase()
	dbList.Map["files"] = OpenFilesDatabase()
	dbList.Map["analytics"] = OpenAnalyticsDatabase()
	dbList.Map["notifications"] = OpenNotificationDatabase()
	dbList.Map["knowledge"] = OpenKnowledgeDatabase()
	dbList.Map["wisdom"] = OpenWisdomDatabase()
	dbList.Map["process"] = OpenProcessDatabase()
	dbList.Map["periodic"] = OpenPeriodicDatabase()
	dbList.Map["stores"] = OpenStoresDatabase()
	dbList.Map["items"] = OpenItemsDatabase()
	dbList.Map["orders"] = OpenOrdersDatabase()
	// Chat Server
	chatServer := CreateChatServer(dbList.Map["msg"])
	// Connector
	connector := CreateConnector(dbList.Map["notifications"])
	// Firebase Cloud Messaging
	fmt.Println(":: Checking for fbcm.json")
	var fcmClient *messaging.Client
	fcmClient = nil
	workDir, _ := os.Getwd()
	fbcm := filepath.Join(workDir, "fbcm.json")
	decodedKey, err := os.ReadFile(fbcm)
	if err == nil {
		opts := []option.ClientOption{option.WithCredentialsJSON(decodedKey)}
		// Initialize firebase app
		app, err := firebase.NewApp(context.Background(), nil, opts...)
		if err != nil {
			fmt.Printf(":: Error initializing firebase app: %s", err)
		}
		fcmClient, err = app.Messaging(context.Background())
		if err != nil {
			fmt.Printf(":: Error initializing firebase client: %s", err)
		} else {
			fmt.Println(":: Firebase Cloud Messaging initialized")
		}
	} else {
		fmt.Println(":: fbcm.json missing")
	}
	// Initialize Emailer
	fmt.Println(":: Initializing Emailer")
	emailClient, err := GetEmailClient(config)
	if err != nil || emailClient == nil {
		fmt.Println(":: Emailer initialization failed")
	} else {
		fmt.Println(":: Emailer initialized")
	}
	// Start Server (with wait group delta)
	wg.Add(1)
	go StartServer(doneServer, &wg, config, dbList, chatServer, connector, fcmClient, emailClient)
	// Start periodic actions loop
	dbList.Map["periodic"].StartPeriodicLoop(donePeriodic, dbList, connector, fcmClient)
	// Wait for all processes to end
	wg.Wait()
}

func getConfig() (Config, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return Config{JwtSecret: "secret"}, errors.New("err retrieving workDir")
	}
	configFilename := filepath.Join(workDir, "config.json")
	if !FileExists(configFilename) {
		return Config{JwtSecret: "secret", Port: "8080"}, nil
	}
	configJson, err := os.ReadFile(configFilename)
	if err != nil {
		return Config{JwtSecret: "secret", Port: "8080"}, errors.New("err reading config.json")
	}
	config := Config{}
	err = json.Unmarshal(configJson, &config)
	if err != nil {
		return Config{JwtSecret: "secret", Port: "8080"}, errors.New("err reading deserialized config.json")
	}
	if config.JwtSecret == "" {
		config.JwtSecret = "secret"
	}
	if config.Port == "" {
		config.Port = "8080"
	}
	return config, nil
}

func dbug() {
	// TestBadger()
	// TestDB()
	// os.Exit(0)
}
