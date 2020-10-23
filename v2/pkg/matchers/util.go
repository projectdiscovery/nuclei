package matchers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultFormat = "%s"

// HTTPToMap Converts HTTP to Matcher Map
func HTTPToMap(resp *http.Response, body, headers string, duration time.Duration, format string) (m map[string]interface{}) {
	m = make(map[string]interface{})

	if format == "" {
		format = defaultFormat
	}

	m[fmt.Sprintf(format, "content_length")] = resp.ContentLength
	m[fmt.Sprintf(format, "status_code")] = resp.StatusCode

	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(k, "-", "_")))
		m[fmt.Sprintf(format, k)] = strings.Join(v, " ")
	}

	m[fmt.Sprintf(format, "all_headers")] = headers
	m[fmt.Sprintf(format, "body")] = body

	if r, err := httputil.DumpResponse(resp, true); err == nil {
		m[fmt.Sprintf(format, "raw")] = string(r)
	}

	// Converts duration to seconds (floating point) for DSL syntax
	m[fmt.Sprintf(format, "duration")] = duration.Seconds()

	return m
}

// DNSToMap Converts DNS to Matcher Map
func DNSToMap(msg *dns.Msg, format string) (m map[string]interface{}) {
	m = make(map[string]interface{})

	if format == "" {
		format = defaultFormat
	}

	m[fmt.Sprintf(format, "rcode")] = msg.Rcode

	var qs string

	for _, question := range msg.Question {
		qs += fmt.Sprintln(question.String())
	}

	m[fmt.Sprintf(format, "question")] = qs

	var exs string
	for _, extra := range msg.Extra {
		exs += fmt.Sprintln(extra.String())
	}

	m[fmt.Sprintf(format, "extra")] = exs

	var ans string
	for _, answer := range msg.Answer {
		ans += fmt.Sprintln(answer.String())
	}

	m[fmt.Sprintf(format, "answer")] = ans

	var nss string
	for _, ns := range msg.Ns {
		nss += fmt.Sprintln(ns.String())
	}

	m[fmt.Sprintf(format, "ns")] = nss
	m[fmt.Sprintf(format, "raw")] = msg.String()

	return m
}
