package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/hillu/go-yara/v4"
)

var errDropped error = fmt.Errorf("%s", "Dropped")

// proxy represents a the internal httpreverseproxy with its rules
type proxy struct {
	proxy   *httputil.ReverseProxy
	yaraIn  *yara.Rules
	yaraOut *yara.Rules
}

// ServeHTTP matches requests to the target server, using the "incoming" rules
func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	debugf("%s", r.URL.String())

	reqDump, err := httputil.DumpRequest(r, true)
	if err != nil {
		log.Printf("Error @ dumping the request: %v\n", err)
	}

	var matchesIn yara.MatchRules
	err = p.yaraIn.ScanMem(reqDump, 0, 5*time.Second, &matchesIn) // TODO: play with ScanFlags
	if err != nil {
		log.Printf("Error @ ScanMem() the request: %v\n", err)
	}

	for _, m := range matchesIn {
		var names []string
		for _, ms := range m.Strings {
			names = append(names, ms.Name)
		}
		// TODO: json export?
		if shouldBeDropped(m.Metas) {
			lm := LogMessage{Action: "Dropped", Src: r.RemoteAddr, Rule: m.Rule, Namespace: m.Namespace, Strings: names}
			log.Println(lm)
			return // drop immediately
		}
		lm := LogMessage{Action: "Matched", Src: r.RemoteAddr, Rule: m.Rule, Namespace: m.Namespace, Strings: names}
		log.Println(lm)
	}

	p.proxy.ServeHTTP(w, r)

}

// errorHandler is called on errors and when a request is dropped, hence the errDropped check
func (p *proxy) errorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	if err != errDropped {
		log.Printf("Error (errorHandler()): %v", err)
	}
	rw.WriteHeader(http.StatusBadRequest)
}

// responseMatcher matches responses from the target server, using the "outgoing" rules
func (p *proxy) responseMatcher(resp *http.Response) error {
	resDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("Error @ dumping the response: %v\n", err)
		return nil
	}

	var matchesOut yara.MatchRules
	err = p.yaraOut.ScanMem(resDump, yara.ScanFlagsFastMode, 5*time.Second, &matchesOut)
	if err != nil {
		log.Printf("Error @ ScanMem() the response: %v\n", err)
		return nil
	}

	for _, m := range matchesOut {
		var names []string
		for _, ms := range m.Strings {
			names = append(names, ms.Name)
		}
		// TODO: json export?
		if shouldBeDropped(m.Metas) {
			lm := LogMessage{Action: "Dropped", Src: resp.Request.RemoteAddr, Rule: m.Rule, Namespace: m.Namespace, Strings: names}
			log.Println(lm)
			return errDropped // drop immediately
		}
		lm := LogMessage{Action: "Matched", Src: resp.Request.RemoteAddr, Rule: m.Rule, Namespace: m.Namespace, Strings: names}
		log.Println(lm)
	}

	return nil

}
