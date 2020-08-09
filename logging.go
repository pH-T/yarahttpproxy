package main

import (
	"fmt"
	"log"
	"strings"
)

type LogMessage struct {
	Action    string   `json:"Action"`
	Src       string   `json:"Src"`
	Rule      string   `json:"Rule"`
	Namespace string   `json:"Namespace"`
	Strings   []string `json:"Strings"`
}

func (lm LogMessage) String() string {
	return fmt.Sprintf("[%s] %s: %s (%s): %s", lm.Src, lm.Action, lm.Rule, lm.Namespace, strings.Join(lm.Strings, ", "))
}

func debugf(format string, v ...interface{}) {
	if debug {
		log.Printf("DEBUG: "+format, v...)
	}
}
