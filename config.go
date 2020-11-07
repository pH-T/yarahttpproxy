package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	RemoteHost string   `json:"remoteHost"`
	LocalAddr  string   `json:"localAddr"`
	RuleFolder string   `json:"ruleFolder"`
	UseHTTPS   bool     `json:"useHTTPS"`
	Domains    []string `json:"domains"`
	Debug      bool     `json:"debug"`
}

func GetConfig(path string) Config {
	file, err := os.Open(path)
	if err != nil {
		fmt.Println("Error @ reading config file: " + err.Error())
		os.Exit(1)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	configuration := Config{}

	err = decoder.Decode(&configuration)
	if err != nil {
		fmt.Println("Error @ reading config file: " + err.Error())
		os.Exit(1)
	}

	// validation
	if configuration.RemoteHost == "" {
		fmt.Println("RemoteHost is missing")
		os.Exit(1)
	}

	if configuration.LocalAddr == "" {
		fmt.Println("LocalAddr is missing")
		os.Exit(1)
	}

	if configuration.RuleFolder == "" {
		fmt.Println("RuleFolder is missing")
		os.Exit(1)
	}

	if configuration.UseHTTPS && len(configuration.Domains) == 0 {
		fmt.Println("Domains are missing")
		os.Exit(1)
	}

	return configuration
}
