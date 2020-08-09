package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

var (
	hostRemote string
	hostLokal  string
	ruleFolder string
	debug      bool
)

func init() {
	flag.StringVar(&hostRemote, "hr", "", "host to forward requests to (e.g. http://localhost:8090)")
	flag.StringVar(&hostLokal, "hl", "127.0.0.1:8080", "host to listen on (e.g. 127.0.0.1:8080)")
	flag.StringVar(&ruleFolder, "rules", "rules/", "folder with all the rules to use")
	flag.BoolVar(&debug, "d", false, "debug flag for logging request/response duration")
	flag.Parse()
}

func main() {
	// input reading & validation
	if hostRemote == "" {
		fmt.Println("-hr is missing!")
		flag.Usage()
		return
	}

	if !strings.HasSuffix(ruleFolder, "/") {
		ruleFolder = ruleFolder + "/"
	}

	remote, err := url.Parse(hostRemote)
	if err != nil {
		log.Fatalf("Error parsing given host: %v", err)
	}

	files, err := ioutil.ReadDir(ruleFolder)
	if err != nil {
		log.Fatalf("Error opening rule folder: %v", err)
	}

	var rulesIn []string
	var rulesOut []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".yar") {
			if strings.HasPrefix(f.Name(), "in.") {
				rulesIn = append(rulesIn, ruleFolder+f.Name())
			} else if strings.HasPrefix(f.Name(), "out.") {
				rulesOut = append(rulesOut, ruleFolder+f.Name())
			}
		}
	}

	proxy := &proxy{proxy: httputil.NewSingleHostReverseProxy(remote), yaraIn: initYara(rulesIn), yaraOut: initYara(rulesOut)}
	proxy.proxy.ModifyResponse = proxy.responseMatcher
	proxy.proxy.ErrorHandler = proxy.errorHandler

	// server setup
	srv := &http.Server{
		Addr:         hostLokal,
		Handler:      proxy,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	log.Println("Listening on: " + hostLokal)
	log.Println(srv.ListenAndServe())
}
