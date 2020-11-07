package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

var debug bool

func main() {

	c := GetConfig("config.json")
	debug = c.Debug

	remote, err := url.Parse(c.RemoteHost)
	if err != nil {
		log.Fatalf("Error parsing given host: %v", err)
	}

	files, err := ioutil.ReadDir(c.RuleFolder)
	if err != nil {
		log.Fatalf("Error opening rule folder: %v", err)
	}

	var rulesIn []string
	var rulesOut []string
	for _, f := range files {
		if !f.IsDir() && strings.HasSuffix(f.Name(), ".yar") {
			if strings.HasPrefix(f.Name(), "in.") {
				rulesIn = append(rulesIn, c.RuleFolder+f.Name())
			} else if strings.HasPrefix(f.Name(), "out.") {
				rulesOut = append(rulesOut, c.RuleFolder+f.Name())
			}
		}
	}

	proxy := &proxy{proxy: httputil.NewSingleHostReverseProxy(remote), yaraIn: initYara(rulesIn), yaraOut: initYara(rulesOut)}
	proxy.proxy.ModifyResponse = proxy.responseMatcher
	proxy.proxy.ErrorHandler = proxy.errorHandler

	if !c.UseHTTPS {
		// server setup
		srv := &http.Server{
			Addr:         c.LocalAddr,
			Handler:      proxy,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 10 * time.Second,
		}

		log.Println("Listening on: " + c.LocalAddr)
		log.Println(srv.ListenAndServe())
	} else {
		log.Println("HTTPS on: " + strings.Join(c.Domains, ", "))
		err := certmagic.HTTPS(c.Domains, proxy)
		if err != nil {
			log.Fatal(err)
		}
	}

}
