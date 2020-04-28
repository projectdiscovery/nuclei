package matchers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"

	"github.com/miekg/dns"
)

func httpToMap(resp *http.Response, body, headers string) (m map[string]interface{}) {
	m = make(map[string]interface{})

	m["content_length"] = resp.ContentLength
	m["status_code"] = resp.StatusCode
	for k, v := range resp.Header {
		k = strings.ToLower(strings.TrimSpace(strings.Replace(k, "-", "_", -1)))
		m[k] = strings.Join(v, " ")
	}
	m["all_headers"] = headers

	m["body"] = body
	if r, err := httputil.DumpResponse(resp, true); err == nil {
		m["raw"] = string(r)
	}

	return m
}

func dnsToMap(msg *dns.Msg) (m map[string]interface{}) {
	m = make(map[string]interface{})

	m["rcode"] = msg.Rcode
	var qs string
	for _, question := range msg.Question {
		qs += fmt.Sprintln(question.String())
	}
	m["question"] = qs

	var exs string
	for _, extra := range msg.Extra {
		exs += fmt.Sprintln(extra.String())
	}
	m["extra"] = exs

	var ans string
	for _, answer := range msg.Answer {
		ans += fmt.Sprintln(answer.String())
	}
	m["answer"] = ans

	var nss string
	for _, ns := range msg.Ns {
		nss += fmt.Sprintln(ns.String())
	}
	m["ns"] = nss

	m["raw"] = msg.String()

	return m
}
