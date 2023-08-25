package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Config struct {
	jwtSecret string
}

func main() {
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
	// Databases
	userDB := OpenUserDatabase()
	chatGroupDB := OpenChatGroupDatabase()
	chatMemberDB := OpenChatMemberDatabase()
	chatMessagesDB := OpenChatMessageDatabase()
	fileDB := OpenFilesDatabase()
	analyticsDB := OpenAnalyticsDatabase()
	notificationDB := OpenNotificationDatabase()
	knowledgeDB := OpenKnowledgeDatabase()
	wisdomDB := OpenWisdomDatabase()
	// Chat Server
	chatServer := CreateChatServer(chatMessagesDB)
	// Connector
	connector := CreateConnector(notificationDB)
	// Start Server (with wait group delta)
	wg.Add(1)
	go StartServer(doneServer, &wg, config,
		userDB, chatGroupDB, chatMemberDB, chatMessagesDB, fileDB, analyticsDB, notificationDB,
		knowledgeDB, wisdomDB,
		chatServer, connector,
	)
	// Start periodic actions loop
	StartPeriodicLoop(donePeriodic)
	// Wait for all processes to end
	wg.Wait()
}

func getConfig() (Config, error) {
	workDir, err := os.Getwd()
	if err != nil {
		return Config{jwtSecret: "secret"}, errors.New("err retrieving workDir")
	}
	configFilename := filepath.Join(workDir, "config.json")
	if !FileExists(configFilename) {
		return Config{jwtSecret: "secret"}, nil
	}
	configJson, err := os.ReadFile(configFilename)
	if err != nil {
		return Config{jwtSecret: "secret"}, errors.New("err reading config.json")
	}
	config := Config{}
	err = json.Unmarshal(configJson, &config)
	if err != nil {
		return Config{jwtSecret: "secret"}, errors.New("err reading deserialized config.json")
	}
	if config.jwtSecret == "" {
		config.jwtSecret = "secret"
	}
	return config, nil
}
