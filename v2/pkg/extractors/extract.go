package extractors

import (
	"net/http"
	"strconv"

	"github.com/miekg/dns"
)

// Extract extracts response from the parts of request using a regex
func (e *Extractor) Extract(resp *http.Response, body, headers string) []map[string]string {
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
	case KValExtractor:
		if e.part == HeaderPart {
			return e.extractKVal(resp)
		} else {
			matches := e.extractKVal(resp)
			if len(matches) > 0 {
				return matches
			}
			return e.extractCookieKVal(resp, "set-cookie")
		}
	}

	return nil
}

// ExtractDNS extracts response from dns message using a regex
func (e *Extractor) ExtractDNS(msg *dns.Msg) []map[string]string {
	switch e.extractorType {
	case RegexExtractor:
		return e.extractRegex(msg.String())
	case KValExtractor:
	}

	return nil
}

// extractRegex extracts text from a corpus and returns it
func (e *Extractor) extractRegex(corpus string) []map[string]string {
	results := make([]map[string]string, 0)
	for _, regex := range e.regexCompiled {
		if e.Group == false {
			cur := map[string]string{}
			matches := regex.FindAllString(corpus, -1)
			for index, match := range matches {
				cur[strconv.Itoa(index)] = match
			}
			results = append(results, cur)
		} else {
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
				// If no tag is provided (?:<test>.*) then use positional matching group numbers
				if tags {
					results = append(results, cur)
				} else {
					results = append(results, positional_cur)
				}
			}
		}
	}
	return results
}

// extractKVal extracts text from http response
func (e *Extractor) extractKVal(r *http.Response) []map[string]string {
	results := make([]map[string]string, 0)
	for _, k := range e.KVal {
		cur := map[string]string{}
		for index, v := range r.Header.Values(k) {
			cur[strconv.Itoa(index)] = v
		}
		results = append(results, cur)
	}
	return results
}

// extractCookieKVal extracts text from cookies
func (e *Extractor) extractCookieKVal(r *http.Response, key string) []map[string]string {
	results := make([]map[string]string, 0)
	for _, k := range e.KVal {
		cur := map[string]string{}
		for index, cookie := range r.Cookies() {
			if cookie.Name == k {
				cur[strconv.Itoa(index)] = cookie.Value
			}
		}
		results = append(results, cur)
	}
	return results
}
