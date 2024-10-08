package main

import (
	"context"
	"encoding/json"
	"errors"
	firebase "firebase.google.com/go"
	"firebase.google.com/go/messaging"
	"fmt"
	"google.golang.org/api/option"
	"os"
	"path/filepath"
	"sync"
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
}

type Databases struct {
	Map map[string]*GoDB
}

func main() {
	// #### RUNTIME
	// runtime.GOMAXPROCS(128)
	// #### DEBUG
	// debug.SetMemoryLimit(700 * MiB)
	dbug()
	// #### Create wait group and done channels
	wg := sync.WaitGroup{}
	doneServer := make(chan bool)
	donePeriodic := make(chan bool)
	// #### Setup
	config, err := getConfig()
	if err != nil {
		fmt.Println(":: Could not retrieve config.json")
	} else {
		fmt.Println(":: config.json loaded")
	}
	// #### Setup Databases
	// #### Instances for each database will be no more as it requires too many resources
	dbList := &Databases{Map: map[string]*GoDB{}}
	// The main database will store most data that is not subject to rapid changes
	dbList.Map["main"] = OpenDB("main")
	// The rapid database will store data being subject to rapid and frequent changes
	dbList.Map["rapid"] = OpenDB("rapid")
	// Connector
	connector := CreateConnector(dbList.Map["rapid"])
	// Chat Server
	chatServer := CreateChatServer(dbList.Map["rapid"], dbList.Map["main"], connector)
	// Synced Room Server
	syncRoomServer := CreateSyncRoomServer(dbList.Map["rapid"], dbList.Map["main"], connector)
	// #### Firebase Cloud Messaging
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
	// #### Initialize Emailer
	fmt.Println(":: Initializing Emailer")
	emailClient, err := GetEmailClient(config)
	if err != nil || emailClient == nil {
		fmt.Println(":: Emailer initialization failed")
	} else {
		fmt.Println(":: Emailer initialized")
	}
	// #### Start Server (with wait group delta)
	wg.Add(1)
	go StartServer(doneServer, donePeriodic, &wg, config, dbList, chatServer, syncRoomServer, connector, fcmClient, emailClient)
	// #### Start periodic actions loop
	dbList.Map["rapid"].StartPeriodicLoop(donePeriodic, dbList, connector, fcmClient)
	// #### Wait for all processes to end
	wg.Wait()
	fmt.Println(":: wikiric process has terminated. Goodbye!")
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
