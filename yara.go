package main

import (
	"log"
	"os"

	"github.com/hillu/go-yara/v4"
)

// shouldBeDropped checks if the meta field 'drop' exists and if so, if its 'true'
func shouldBeDropped(ms []yara.Meta) bool {
	for _, m := range ms {
		if m.Identifier == "drop" {
			if m.Value.(bool) {
				return true
			} else {
				return false
			}
		}
	}
	return true // TODO: make this a setting
}

// initYara loads the rules from the given files
func initYara(ruleFiles []string) *yara.Rules {
	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}

	for _, rule := range ruleFiles {
		f, err := os.Open(rule)
		if err != nil {
			log.Fatalf("Could not open rule file %s: %v", rule, err)
		}
		err = c.AddFile(f, "httpproxy-"+rule)
		f.Close()
		if err != nil {
			log.Fatalf("Could not parse rule file %s: %v", rule, err)
		}
	}

	rs, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %v", err)
	}

	return rs
}
