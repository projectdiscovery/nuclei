package ssl

import (
	"context"
	"crypto/tls"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network/networkclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/others/utils"
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

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	address, err := getAddress(input)
	if err != nil {
		return nil
	}
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
		event.OperatorsResult, ok = r.CompiledOperators.Execute(data, utils.MatchFunc, utils.ExtractFunc)
		if ok && event.OperatorsResult != nil {
			event.Results = utils.MakeResultEvent(event, r.makeResultEventItem)
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
