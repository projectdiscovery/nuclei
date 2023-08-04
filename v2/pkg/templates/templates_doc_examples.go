// Package templates
// nolint //do not lint as examples with no usage
package templates

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network"
)

var (
	exampleInfoStructure = model.Info{
		Name:           "Argument Injection in Ruby Dragonfly",
		Authors:        stringslice.StringSlice{Value: "0xspara"},
		SeverityHolder: severity.Holder{Severity: severity.High},
		Reference:      stringslice.NewRawStringSlice("https://zxsecurity.co.nz/research/argunment-injection-ruby-dragonfly/"),
		Tags:           stringslice.StringSlice{Value: "cve,cve2021,rce,ruby"},
	}
	exampleNormalHTTPRequest = &http.Request{
		Method: http.HTTPMethodTypeHolder{MethodType: http.HTTPGet},
		Path:   []string{"{{BaseURL}}/.git/config"},
		Operators: operators.Operators{
			MatchersCondition: "and",
			Matchers: []*matchers.Matcher{
				{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Words: []string{"[core]"}},
				{Type: matchers.MatcherTypeHolder{MatcherType: matchers.DSLMatcher}, DSL: []string{"!contains(tolower(body), '<html')", "!contains(tolower(body), '<body')"}, Condition: "and"},
				{Type: matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher}, Status: []int{200}}},
		},
	}
	_ = exampleNormalHTTPRequest

	recursion               = false
	exampleNormalDNSRequest = &dns.Request{
		Name:        "{{FQDN}}",
		RequestType: dns.DNSRequestTypeHolder{DNSRequestType: dns.CNAME},
		Class:       "inet",
		Retries:     2,
		Recursion:   &recursion,
		Operators: operators.Operators{
			Extractors: []*extractors.Extractor{
				{Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{"ec2-[-\\d]+\\.compute[-\\d]*\\.amazonaws\\.com", "ec2-[-\\d]+\\.[\\w\\d\\-]+\\.compute[-\\d]*\\.amazonaws\\.com"}},
			},
		},
	}
	_ = exampleNormalDNSRequest

	exampleNormalFileRequest = &file.Request{
		Extensions: []string{"all"},
		Operators: operators.Operators{
			Extractors: []*extractors.Extractor{
				{Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor}, Regex: []string{"amzn\\.mws\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"}},
			},
		},
	}
	_ = exampleNormalFileRequest

	exampleNormalNetworkRequest = &network.Request{
		Inputs:   []*network.Input{{Data: "envi\r\nquit\r\n"}},
		Address:  []string{"{{Hostname}}", "{{Hostname}}:2181"},
		ReadSize: 2048,
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{
				{Type: matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher}, Words: []string{"zookeeper.version"}},
			},
		},
	}
	_ = exampleNormalNetworkRequest
)
