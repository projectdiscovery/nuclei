package capture_group_extractors

import (
	"github.com/miekg/dns"
	"net/http"
	"strconv"
)

// Extract extracts response from the parts of request using a regex
func (e *CaptureGroupExtractor) Extract(resp *http.Response, body, headers string) []map[string]string {
	switch e.extractorType {
	case RegexExtractor:
		if e.part == BodyPart {
			return e.extractRegex(body)
		} else if e.part == HeaderPart {
			return e.extractRegex(headers)
		} else {
			matches := e.extractRegex(headers)
			matches = append(matches,e.extractRegex(body)...)
			return matches
		}
	}

	return nil
}

// ExtractDNS extracts response from dns message using a regex
func (e *CaptureGroupExtractor) ExtractDNS(msg *dns.Msg) []map[string]string {
	switch e.extractorType {
	case RegexExtractor:
		return e.extractRegex(msg.String())
	}

	return nil
}

// extractRegex extracts text from a corpus and returns it
func (e *CaptureGroupExtractor) extractRegex(corpus string) []map[string]string {
	results := make([]map[string]string, 0)
	for _, regex := range e.regexCompiled {
		tags := false
		matches := regex.FindAllStringSubmatch(corpus, -1)
		for _, match := range matches {
			cur := map[string]string{}
			positional_cur := map[string]string{}
			for i, tag := range regex.SubexpNames() {
				positional_cur[strconv.Itoa(i)] = match[i]
				if tag != "" {
					tags = true
					cur[tag] = match[i]
				}
			}
			if tags {
				results = append(results, cur)
			} else {
				results = append(results, positional_cur)
			}
		}
	}
	return results
}
