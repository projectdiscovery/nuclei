package waf

import (
	_ "embed"
	"encoding/json"
	"log"
	"regexp"
)

type WafDetector struct {
	wafs       map[string]waf
	regexCache map[string]*regexp.Regexp
}

// waf represents a web application firewall definition
type waf struct {
	Company string `json:"company"`
	Name    string `json:"name"`
	Regex   string `json:"regex"`
}

// wafData represents the root JSON structure
type wafData struct {
	WAFs map[string]waf `json:"wafs"`
}

//go:embed regexes.json
var wafContentRegexes string

func NewWafDetector() *WafDetector {
	var data wafData
	if err := json.Unmarshal([]byte(wafContentRegexes), &data); err != nil {
		log.Printf("could not unmarshal waf content regexes: %s", err)
	}

	store := &WafDetector{
		wafs:       data.WAFs,
		regexCache: make(map[string]*regexp.Regexp),
	}

	for id, waf := range store.wafs {
		if waf.Regex == "" {
			continue
		}
		compiled, err := regexp.Compile(waf.Regex)
		if err != nil {
			log.Printf("invalid WAF regex for %s: %v", id, err)
			continue
		}
		store.regexCache[id] = compiled
	}
	return store
}

func (d *WafDetector) DetectWAF(content string) (string, bool) {
	for id, regex := range d.regexCache {
		if regex.MatchString(content) {
			return id, true
		}
	}
	return "", false
}

func (d *WafDetector) GetWAF(id string) (waf, bool) {
	waf, ok := d.wafs[id]
	return waf, ok
}
