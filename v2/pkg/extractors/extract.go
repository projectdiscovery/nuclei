package extractors

import (
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// Extract extracts response from the parts of request using a regex
func (e *Extractor) Extract(resp *http.Response, body, headers string) map[string]struct{} {
	switch e.extractorType {
	case RegexExtractor:
		if e.part == BodyPart {
			return e.extractRegex(body)
		} else if e.part == HeaderPart {
			return e.extractRegex(headers)
		} else {
			matches := e.extractRegex(headers)
			if len(matches) > 0 {
				return matches
			}
			return e.extractRegex(body)
		}
	case KValExtractor:
		if e.part == HeaderPart {
			return e.extractKVal(resp)
		} else {
			matches := e.extractKVal(resp)
			if len(matches) > 0 {
				return matches
			}
			return e.extractInlineKVal(resp, "cookies")
		}
	}

	return nil
}

// ExtractDNS extracts response from dns message using a regex
func (e *Extractor) ExtractDNS(msg *dns.Msg) map[string]struct{} {
	switch e.extractorType {
	case RegexExtractor:
		return e.extractRegex(msg.String())
	case KValExtractor:
	}

	return nil
}

// extractRegex extracts text from a corpus and returns it
func (e *Extractor) extractRegex(corpus string) map[string]struct{} {
	results := make(map[string]struct{})
	for _, regex := range e.regexCompiled {
		matches := regex.FindAllString(corpus, -1)
		for _, match := range matches {
			results[match] = struct{}{}
		}
	}
	return results
}

// extractKVal extracts text from http response
func (e *Extractor) extractKVal(r *http.Response) map[string]struct{} {
	results := make(map[string]struct{})
	for _, k := range e.KVal {
		for _, v := range r.Header.Values(k) {
			results[v] = struct{}{}
		}
	}
	return results
}

// extractInlineKVal extracts text from inline corpus
func (e *Extractor) extractInlineKVal(r *http.Response, key string) map[string]struct{} {
	results := make(map[string]struct{})
	for _, v := range r.Header.Values(key) {
		for _, token := range strings.Split(v, " ") {
			semicolon := strings.Index(token, ":")
			key, value := token[:semicolon], token[semicolon:]
			for _, k := range e.KVal {
				if key == k {
					results[value] = struct{}{}
				}
			}
		}
	}
	return results
}
