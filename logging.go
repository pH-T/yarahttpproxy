package main

import (
	"fmt"
	"log"
	"strings"
)

var debug bool

// LogMessage represents a log entry
type LogMessage struct {
	Action    string   `json:"Action"`
	Src       string   `json:"Src"`
	Rule      string   `json:"Rule"`
	Namespace string   `json:"Namespace"`
	Strings   []string `json:"Strings"`
}

// String returnes a nice presentation of the LogMessage
func (lm LogMessage) String() string {
	return fmt.Sprintf("[%s] %s: %s (%s): %s", lm.Src, lm.Action, lm.Rule, lm.Namespace, strings.Join(lm.Strings, ", "))
}

// debugf calls log.Printf(...) if debug is set to true
func debugf(format string, v ...interface{}) {
	if debug {
		log.Printf("DEBUG: "+format, v...)
	}
}
