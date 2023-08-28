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
	processDB := OpenProcessDatabase()
	// Chat Server
	chatServer := CreateChatServer(chatMessagesDB)
	// Connector
	connector := CreateConnector(notificationDB)
	// Start Server (with wait group delta)
	wg.Add(1)
	go StartServer(doneServer, &wg, config,
		userDB, chatGroupDB, chatMemberDB, chatMessagesDB, fileDB, analyticsDB, notificationDB,
		knowledgeDB, wisdomDB, processDB,
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

func dbug() {
	TestDB()
	// wisdom1 := &Wisdom{
	// 	Description: "I like ice-cream cones. iced cream is what I like. ice!!!",
	// }
	// wisdom2 := &Wisdom{
	// 	Description: "creamy iced meat cones with ice",
	// }
	// wisdom3 := &Wisdom{
	// 	Description: "cream-cones are insane with ice in them!",
	// }
	// wisdom4 := &Wisdom{
	// 	Description: "icecream cones",
	// }
	// query := &WisdomQuery{Query: "ice cream cones", Fields: "usr,desc"}
	// // Turn query text into a full regex pattern
	// words, p := GetRegexQuery(query.Query)
	// accuracy, points := GetWisdomQueryPoints(wisdom1, query, p, words, true)
	// fmt.Println("ICE CREAM:    ", decimal.NewFromFloat(accuracy).Round(3).String(), "%", points)
	// accuracy, points = GetWisdomQueryPoints(wisdom2, query, p, words, false)
	// fmt.Println("CREAMED MEAT: ", decimal.NewFromFloat(accuracy).Round(3).String(), "%", points)
	// accuracy, points = GetWisdomQueryPoints(wisdom3, query, p, words, true)
	// fmt.Println("CREAM CONES:  ", decimal.NewFromFloat(accuracy).Round(3).String(), "%", points)
	// accuracy, points = GetWisdomQueryPoints(wisdom4, query, p, words, false)
	// fmt.Println("ICC:          ", decimal.NewFromFloat(accuracy).Round(3).String(), "%", points)
	os.Exit(0)
}
