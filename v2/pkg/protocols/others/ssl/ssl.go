package ssl

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network/networkclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Request is a request for the SSL protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	// cache any variables that may be needed for operation.
	dialer  *fastdialer.Dialer
	options *protocols.ExecuterOptions
}

// Compile compiles the request generators preparing any requests possible.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options

	client, err := networkclientpool.Get(options.Options, &networkclientpool.Configuration{})
	if err != nil {
		return errors.Wrap(err, "could not get network client")
	}
	r.dialer = client

	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (r *Request) Requests() int {
	return 1
}

// GetID returns the ID for the request if any.
func (r *Request) GetID() string {
	return ""
}

// Match performs matching operation for a matcher on model and returns true or false.
func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) bool {
	partItem, ok := data[matcher.Part]
	if !ok {
		return false
	}
	item := types.ToString(partItem)

	switch matcher.GetType() {
	case matchers.SizeMatcher:
		return matcher.Result(matcher.MatchSize(len(item)))
	case matchers.WordsMatcher:
		return matcher.Result(matcher.MatchWords(item))
	case matchers.RegexMatcher:
		return matcher.Result(matcher.MatchRegex(item))
	case matchers.BinaryMatcher:
		return matcher.Result(matcher.MatchBinary(item))
	case matchers.DSLMatcher:
		return matcher.Result(matcher.MatchDSL(data))
	}
	return false
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (r *Request) Extract(data map[string]interface{}, extractor *extractors.Extractor) map[string]struct{} {
	item, ok := data[extractor.Part]
	if !ok {
		return nil
	}
	itemStr := types.ToString(item)

	switch extractor.GetType() {
	case extractors.RegexExtractor:
		return extractor.ExtractRegex(itemStr)
	case extractors.KValExtractor:
		return extractor.ExtractKval(data)
	}
	return nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	address, err := getAddress(input)
	if err != nil {
		return nil
	}
	fmt.Printf("address: %v\n", address)
	hostname, _, _ := net.SplitHostPort(input)

	config := &tls.Config{InsecureSkipVerify: true, ServerName: hostname}
	conn, err := r.dialer.DialTLSWithConfig(context.Background(), "tcp", address, config)
	if err != nil {
		r.options.Output.Request(r.options.TemplateID, input, "ssl", err)
		r.options.Progress.IncrementFailedRequestsBy(1)
		return errors.Wrap(err, "could not connect to server")
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Duration(r.options.Options.Timeout) * time.Second))

	connTLS, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	if len(connTLS.ConnectionState().PeerCertificates) == 0 {
		return nil
	}
	data := make(map[string]interface{})
	cert := connTLS.ConnectionState().PeerCertificates[0]
	data["host"] = input
	data["not_after"] = cert.NotAfter
	data["ip"] = r.dialer.GetDialedIP(hostname)

	event := &output.InternalWrappedEvent{InternalEvent: data}
	if r.CompiledOperators != nil {
		var ok bool
		event.OperatorsResult, ok = r.CompiledOperators.Execute(data, r.Match, r.Extract)
		if ok && event.OperatorsResult != nil {
			event.Results = r.makeResultEvent(event)
		}
		callback(event)
	}
	return nil
}

// getAddress returns the address of the host to make request to
func getAddress(toTest string) (string, error) {
	if strings.Contains(toTest, "://") {
		parsed, err := url.Parse(toTest)
		if err != nil {
			return "", err
		}
		_, port, _ := net.SplitHostPort(parsed.Host)

		if parsed.Scheme == "https" && port == "" {
			toTest = net.JoinHostPort(parsed.Host, "443")
		} else {
			toTest = parsed.Host
		}
	}
	return toTest, nil
}

// makeResultEvent creates a result event from internal wrapped event
func (r *Request) makeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	if len(wrapped.OperatorsResult.DynamicValues) > 0 {
		return nil
	}
	results := make([]*output.ResultEvent, 0, len(wrapped.OperatorsResult.Matches)+1)

	// If we have multiple matchers with names, write each of them separately.
	if len(wrapped.OperatorsResult.Matches) > 0 {
		for k := range wrapped.OperatorsResult.Matches {
			data := r.makeResultEventItem(wrapped)
			data.MatcherName = k
			results = append(results, data)
		}
	} else if len(wrapped.OperatorsResult.Extracts) > 0 {
		for k, v := range wrapped.OperatorsResult.Extracts {
			data := r.makeResultEventItem(wrapped)
			data.ExtractedResults = v
			data.ExtractorName = k
			results = append(results, data)
		}
	} else {
		data := r.makeResultEventItem(wrapped)
		results = append(results, data)
	}
	return results
}

func (r *Request) makeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(r.options.TemplateID),
		TemplatePath:     types.ToString(r.options.TemplatePath),
		Info:             r.options.TemplateInfo,
		Type:             "ssl",
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Matched:          types.ToString(wrapped.InternalEvent["host"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		IP:               types.ToString(wrapped.InternalEvent["ip"]),
	}
	return data
}
