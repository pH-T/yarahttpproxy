package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/hillu/go-yara/v4"
)

var droppedError error = fmt.Errorf("%s", "Dropped")

type proxy struct {
	proxy   *httputil.ReverseProxy
	yaraIn  *yara.Rules
	yaraOut *yara.Rules
}

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

	if len(matchesIn) > 0 {
		for _, m := range matchesIn {
			var names []string
			for _, ms := range m.Strings {
				names = append(names, ms.Name)
			}
			// TODO: json export?
			if shouldBeDropped(m.Metas) {
				lm := LogMessage{Action: "Dropped", Src: r.RemoteAddr, Rule: m.Rule, Namespace: m.Namespace, Strings: names}
				log.Println(lm)
				return
			}
			lm := LogMessage{Action: "Matched", Src: r.RemoteAddr, Rule: m.Rule, Namespace: m.Namespace, Strings: names}
			log.Println(lm)
		}
	}

	p.proxy.ServeHTTP(w, r)

}

// errorHandler is called on errors and when a request is dropped, hence the droppedError check
func (p *proxy) errorHandler(rw http.ResponseWriter, req *http.Request, err error) {
	if err != droppedError {
		log.Printf("Error (errorHandler()): %v", err)
	}
	rw.WriteHeader(http.StatusBadRequest)
}

func (p *proxy) responseMatcher(resp *http.Response) error {
	resDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		log.Printf("Error @ dumping the response: %v\n", err)
		return nil
	}

	var matchesOut yara.MatchRules
	err = p.yaraOut.ScanMem(resDump, 0, 5*time.Second, &matchesOut) // TODO: play with ScanFlags
	if err != nil {
		log.Printf("Error @ ScanMem() the response: %v\n", err)
		return nil
	}

	if len(matchesOut) > 0 {
		for _, m := range matchesOut {
			var names []string
			for _, ms := range m.Strings {
				names = append(names, ms.Name)
			}
			// TODO: json export?
			if shouldBeDropped(m.Metas) {
				lm := LogMessage{Action: "Dropped", Src: resp.Request.RemoteAddr, Rule: m.Rule, Namespace: m.Namespace, Strings: names}
				log.Println(lm)
				return droppedError
			}
			lm := LogMessage{Action: "Matched", Src: resp.Request.RemoteAddr, Rule: m.Rule, Namespace: m.Namespace, Strings: names}
			log.Println(lm)
		}
	}

	body := ioutil.NopCloser(bytes.NewReader(resDump))
	resp.Body = body
	resp.ContentLength = int64(len(resDump))
	resp.Header.Set("Content-Length", strconv.Itoa(len(resDump)))
	return nil
}
