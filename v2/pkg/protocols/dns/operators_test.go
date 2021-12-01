package dns

import (
	"net"
	"strconv"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func TestResponseToDSLMap(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-dns"
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     5,
		ID:          templateID,
		Recursion:   false,
		Name:        "{{FQDN}}",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile dns request")

	req := new(dns.Msg)
	req.Question = append(req.Question, dns.Question{Name: "one.one.one.one.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = append(resp.Answer, &dns.A{A: net.ParseIP("1.1.1.1"), Hdr: dns.RR_Header{Name: "one.one.one.one."}})

	event := request.responseToDSLMap(req, resp, "one.one.one.one", "one.one.one.one", nil)
	require.Len(t, event, 14, "could not get correct number of items in dsl map")
	require.Equal(t, dns.RcodeSuccess, event["rcode"], "could not get correct rcode")
}

func TestDNSOperatorMatch(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-dns"
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     5,
		ID:          templateID,
		Recursion:   false,
		Name:        "{{FQDN}}",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile dns request")

	req := new(dns.Msg)
	req.Question = append(req.Question, dns.Question{Name: "one.one.one.one.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = append(resp.Answer, &dns.A{A: net.ParseIP("1.1.1.1"), Hdr: dns.RR_Header{Name: "one.one.one.one."}})

	event := request.responseToDSLMap(req, resp, "one.one.one.one", "one.one.one.one", nil)

	t.Run("valid", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:  "raw",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"1.1.1.1"},
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatch, matched := request.Match(event, matcher)
		require.True(t, isMatch, "could not match valid response")
		require.Equal(t, matcher.Words, matched)
	})

	t.Run("rcode", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:   "rcode",
			Type:   matchers.MatcherTypeHolder{MatcherType: matchers.StatusMatcher},
			Status: []int{dns.RcodeSuccess},
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile rcode matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid rcode response")
		require.Equal(t, []string{}, matched)
	})

	t.Run("negative", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:     "raw",
			Type:     matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Negative: true,
			Words:    []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile negative matcher")

		isMatched, matched := request.Match(event, matcher)
		require.True(t, isMatched, "could not match valid negative response matcher")
		require.Equal(t, []string{}, matched)
	})

	t.Run("invalid", func(t *testing.T) {
		matcher := &matchers.Matcher{
			Part:  "raw",
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"random"},
		}
		err := matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatched, matched := request.Match(event, matcher)
		require.False(t, isMatched, "could match invalid response matcher")
		require.Equal(t, []string{}, matched)
	})

	t.Run("caseInsensitive", func(t *testing.T) {
		req := new(dns.Msg)
		req.Question = append(req.Question, dns.Question{Name: "ONE.ONE.ONE.ONE.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

		resp := new(dns.Msg)
		resp.Rcode = dns.RcodeSuccess
		resp.Answer = append(resp.Answer, &dns.A{A: net.ParseIP("1.1.1.1"), Hdr: dns.RR_Header{Name: "ONE.ONE.ONE.ONE."}})

		event := request.responseToDSLMap(req, resp, "ONE.ONE.ONE.ONE", "ONE.ONE.ONE.ONE", nil)

		matcher := &matchers.Matcher{
			Part:            "raw",
			Type:            matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words:           []string{"one.ONE.one.ONE"},
			CaseInsensitive: true,
		}
		err = matcher.CompileMatchers()
		require.Nil(t, err, "could not compile matcher")

		isMatch, matched := request.Match(event, matcher)
		require.True(t, isMatch, "could not match valid response")
		require.Equal(t, []string{"one.one.one.one"}, matched)
	})
}

func TestDNSOperatorExtract(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-dns"
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     5,
		ID:          templateID,
		Recursion:   false,
		Name:        "{{FQDN}}",
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile dns request")

	req := new(dns.Msg)
	req.Question = append(req.Question, dns.Question{Name: "one.one.one.one.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = append(resp.Answer, &dns.A{A: net.ParseIP("1.1.1.1"), Hdr: dns.RR_Header{Name: "one.one.one.one."}})

	event := request.responseToDSLMap(req, resp, "one.one.one.one", "one.one.one.one", nil)

	t.Run("extract", func(t *testing.T) {
		extractor := &extractors.Extractor{
			Part:  "raw",
			Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
			Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extractor valid response")
		require.Equal(t, map[string]struct{}{"1.1.1.1": {}}, data, "could not extract correct data")
	})

	t.Run("kval", func(t *testing.T) {
		extractor := &extractors.Extractor{
			Type: extractors.ExtractorTypeHolder{ExtractorType: extractors.KValExtractor},
			KVal: []string{"rcode"},
		}
		err = extractor.CompileExtractors()
		require.Nil(t, err, "could not compile kval extractor")

		data := request.Extract(event, extractor)
		require.Greater(t, len(data), 0, "could not extractor kval valid response")
		require.Equal(t, map[string]struct{}{strconv.Itoa(dns.RcodeSuccess): {}}, data, "could not extract correct kval data")
	})
}

func TestDNSMakeResult(t *testing.T) {
	options := testutils.DefaultOptions

	testutils.Init(options)
	templateID := "testing-dns"
	request := &Request{
		RequestType: DNSRequestTypeHolder{DNSRequestType: A},
		Class:       "INET",
		Retries:     5,
		ID:          templateID,
		Recursion:   false,
		Name:        "{{FQDN}}",
		Operators: operators.Operators{
			Matchers: []*matchers.Matcher{{
				Name:  "test",
				Part:  "raw",
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"1.1.1.1"},
			}},
			Extractors: []*extractors.Extractor{{
				Part:  "raw",
				Type:  extractors.ExtractorTypeHolder{ExtractorType: extractors.RegexExtractor},
				Regex: []string{"[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+"},
			}},
		},
	}
	executerOpts := testutils.NewMockExecuterOptions(options, &testutils.TemplateInfo{
		ID:   templateID,
		Info: model.Info{SeverityHolder: severity.Holder{Severity: severity.Low}, Name: "test"},
	})
	err := request.Compile(executerOpts)
	require.Nil(t, err, "could not compile dns request")

	req := new(dns.Msg)
	req.Question = append(req.Question, dns.Question{Name: "one.one.one.one.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	resp := new(dns.Msg)
	resp.Rcode = dns.RcodeSuccess
	resp.Answer = append(resp.Answer, &dns.A{A: net.ParseIP("1.1.1.1"), Hdr: dns.RR_Header{Name: "one.one.one.one."}})

	event := request.responseToDSLMap(req, resp, "one.one.one.one", "one.one.one.one", nil)
	finalEvent := &output.InternalWrappedEvent{InternalEvent: event}
	if request.CompiledOperators != nil {
		result, ok := request.CompiledOperators.Execute(event, request.Match, request.Extract, false)
		if ok && result != nil {
			finalEvent.OperatorsResult = result
			finalEvent.Results = request.MakeResultEvent(finalEvent)
		}
	}
	require.Equal(t, 1, len(finalEvent.Results), "could not get correct number of results")
	resultEvent := finalEvent.Results[0]
	require.Equal(t, "test", resultEvent.MatcherName, "could not get correct matcher name of results")
	require.Equal(t, "1.1.1.1", resultEvent.ExtractedResults[0], "could not get correct extracted results")
	require.Equal(t, "one.one.one.one", resultEvent.Matched, "could not get matched value")
}
