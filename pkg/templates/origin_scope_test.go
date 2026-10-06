package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
)

func TestTemplateIsOriginScoped(t *testing.T) {
	root := &http.Request{Path: []string{"{{RootURL}}/health"}}
	if !(&Template{RequestsHTTP: []*http.Request{root}}).IsOriginScoped() {
		t.Fatal("a root-url template should run once per origin")
	}
	if (&Template{RequestsHTTP: []*http.Request{{Path: []string{"{{BaseURL}}/health"}}}}).IsOriginScoped() {
		t.Fatal("a base-url suffix still depends on the crawled path")
	}
	if (&Template{Flow: "http(0)", RequestsHTTP: []*http.Request{root}}).IsOriginScoped() {
		t.Fatal("flow templates are not origin scoped")
	}
	if (&Template{
		RequestsHTTP: []*http.Request{root},
		RequestsDNS:  []*dns.Request{{}},
	}).IsOriginScoped() {
		t.Fatal("another protocol block keeps the template per target")
	}
	if (&Template{RequestsHTTP: []*http.Request{root, {Path: []string{"{{BaseURL}}/login"}}}}).IsOriginScoped() {
		t.Fatal("one target-path request disqualifies the template")
	}
	if (&Template{RequestsHTTP: []*http.Request{root, nil}}).IsOriginScoped() {
		t.Fatal("a nil request is not origin scoped")
	}
	if (&Template{}).IsOriginScoped() {
		t.Fatal("a template with no http requests is not origin scoped")
	}
}
