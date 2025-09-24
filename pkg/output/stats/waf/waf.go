package waf

import (
	_ "embed"
	"encoding/json"
	"log"
	"regexp"
	"runtime"
	"strings"
	"sync"
)

type WafDetector struct {
	wafs       map[string]waf
	regexCache map[string]*regexp.Regexp
	mu         sync.RWMutex
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
	if d == nil || d.regexCache == nil || len(content) == 0 {
		return "", false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	// Limit content size to prevent regex catastrophic backtracking
	maxContentSize := 50000 // 50KB limit
	if len(content) > maxContentSize {
		content = content[:maxContentSize]
	}

	for id, regex := range d.regexCache {
		if regex == nil {
			continue
		}

		// Safely test each regex with panic recovery
		matched := func() bool {
			defer func() {
				if r := recover(); r != nil {
					// Get stack trace and format in one line
					buf := make([]byte, 4096)
					n := runtime.Stack(buf, false)
					stack := strings.ReplaceAll(string(buf[:n]), "\n", " | ")

					log.Printf("regex panic for WAF %s: %v: %v", id, r, stack)
				}
			}()
			return regex.MatchString(content)
		}()

		if matched {
			return id, true
		}
	}

	return "", false
}

func (d *WafDetector) GetWAF(id string) (waf, bool) {
	if d == nil {
		return waf{}, false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	waf, ok := d.wafs[id]
	return waf, ok
}
