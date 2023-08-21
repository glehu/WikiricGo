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
	// Create wait group and done channel
	wg := sync.WaitGroup{}
	done := make(chan bool)
	// Setup
	config, err := getConfig()
	if err != nil {
		fmt.Println(":: Could not retrieve config.json")
	} else {
		fmt.Println(":: config.json loaded")
	}
	// Databases
	setupDatabases()
	// Start Server (with wait group delta)
	wg.Add(1)
	go StartServer(done, &wg, config)
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

func setupDatabases() {
	// TestDB()
}
