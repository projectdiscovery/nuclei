package executer

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/internal/bufwriter"
	"github.com/projectdiscovery/nuclei/v2/internal/progress"
	"github.com/projectdiscovery/nuclei/v2/internal/tracelog"
	"github.com/projectdiscovery/nuclei/v2/pkg/colorizer"
	"github.com/projectdiscovery/nuclei/v2/pkg/matchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/requests"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	retryabledns "github.com/projectdiscovery/retryabledns"
)

// NetworkExecuter is a client for performing a network request
// for a template.
type NetworkExecuter struct {
	coloredOutput  bool
	debug          bool
	jsonOutput     bool
	jsonRequest    bool
	noMeta         bool
	Results        bool
	traceLog       tracelog.Log
	dnsClient      *retryabledns.Client
	template       *templates.Template
	networkRequest *requests.NetworkRequest
	writer         *bufwriter.Writer

	colorizer   colorizer.NucleiColorizer
	decolorizer *regexp.Regexp
}

// NetworkOptions contains configuration options for the Network executer.
type NetworkOptions struct {
	ColoredOutput  bool
	Debug          bool
	JSON           bool
	JSONRequests   bool
	NoMeta         bool
	TraceLog       tracelog.Log
	Template       *templates.Template
	NetworkRequest *requests.NetworkRequest
	Writer         *bufwriter.Writer

	Colorizer   colorizer.NucleiColorizer
	Decolorizer *regexp.Regexp
}

const defaultDNSRetries = 5

// NewNetworkExecuter creates a new Network executer from a template
// and a Network request query.
func NewNetworkExecuter(options *NetworkOptions) *NetworkExecuter {
	dnsClient := retryabledns.New(DefaultResolvers, defaultDNSRetries)

	executer := &NetworkExecuter{
		debug:          options.Debug,
		noMeta:         options.NoMeta,
		jsonOutput:     options.JSON,
		traceLog:       options.TraceLog,
		jsonRequest:    options.JSONRequests,
		dnsClient:      dnsClient,
		template:       options.Template,
		networkRequest: options.NetworkRequest,
		writer:         options.Writer,
		coloredOutput:  options.ColoredOutput,
		colorizer:      options.Colorizer,
		decolorizer:    options.Decolorizer,
	}
	return executer
}

var readDuration = 5 * time.Second

// ExecuteNetwork executes the DNS request on a URL
func (e *NetworkExecuter) ExecuteNetwork(p *progress.Progress, reqURL string) *Result {
	var err error
	result := &Result{}

	// We can't really process http urls
	if strings.HasPrefix(reqURL, "http") {
		err = errors.New("could not process invalid network host")
		e.traceLog.Request(e.template.ID, reqURL, "network", err)
		result.Error = err
		p.Drop(1)
		return result
	}

	var host, port string
	if strings.Contains(reqURL, ":") {
		host, port, err = net.SplitHostPort(reqURL)
	} else {
		port = e.networkRequest.GetPort()
		host = reqURL
	}
	if err != nil {
		e.traceLog.Request(e.template.ID, reqURL, "network", err)
		result.Error = errors.Wrap(err, "could not parse host:port for network request")
		p.Drop(1)
		return result
	}

	var ipAddress string
	if net.ParseIP(host) == nil {
		results, err := e.dnsClient.Resolve(host)
		if err == nil && len(results.IPs) == 0 {
			err = errors.New("no ips found for host")
		}
		if err != nil {
			e.traceLog.Request(e.template.ID, reqURL, "network", err)
			result.Error = errors.Wrap(err, "could not resolve domain")
			p.Drop(1)
			return result
		}
		ipAddress = results.IPs[0]
	} else {
		ipAddress = host
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(ipAddress, port))
	if err != nil {
		e.traceLog.Request(e.template.ID, reqURL, "network", err)
		result.Error = errors.Wrap(err, "could not resolve network address")
		p.Drop(1)
		return result
	}

	conn, err := net.DialTCP("tcp", nil, tcpAddr)
	if err != nil {
		e.traceLog.Request(e.template.ID, reqURL, "network", err)
		result.Error = errors.Wrap(err, "could not dial network address")
		p.Drop(1)
		return result
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(readDuration))

	_, err = conn.Write([]byte(e.networkRequest.Payload))
	if err != nil {
		e.traceLog.Request(e.template.ID, reqURL, "network", err)
		result.Error = errors.Wrap(err, "could not write to network address")
		p.Drop(1)
		return result
	}

	if e.debug {
		gologger.Infof("Dumped Network request for %s (%s)\n\n", reqURL, e.template.ID)
		fmt.Fprintf(os.Stderr, "%s\n", e.networkRequest.Payload)
	}
	gologger.Verbosef("Sent for [%s] to %s\n", "network-request", e.template.ID, reqURL)

	bufferSize := 1024
	if e.networkRequest.ReadSize != 0 {
		bufferSize = e.networkRequest.ReadSize
	}
	buffer := &bytes.Buffer{}
	buffer.Grow(bufferSize)

	connbuf := bufio.NewReader(conn)
	for {
		str, err := connbuf.ReadString('\n')
		if err != nil {
			break
		}
		buffer.WriteString(str)
	}

	p.Update()
	e.traceLog.Request(e.template.ID, reqURL, "network", nil)

	replyStr := buffer.String()
	if e.debug {
		gologger.Infof("Dumped Network response for %s (%s)\n\n", reqURL, e.template.ID)
		fmt.Fprintf(os.Stderr, "%s\n", replyStr)
	}

	matcherCondition := e.networkRequest.GetMatchersCondition()
	for _, matcher := range e.networkRequest.Matchers {
		// Check if the matcher matched
		if !matcher.MatchNetwork(replyStr) {
			// If the condition is AND we haven't matched, return.
			if matcherCondition == matchers.ANDCondition {
				return result
			}
		} else {
			// If the matcher has matched, and its an OR
			// write the first output then move to next matcher.
			if matcherCondition == matchers.ORCondition && len(e.networkRequest.Extractors) == 0 {
				e.writeOutputNetwork(reqURL, e.networkRequest.Payload, replyStr, matcher, nil)
				result.GotResults = true
			}
		}
	}

	// All matchers have successfully completed so now start with the
	// next task which is extraction of input from matchers.
	var extractorResults []string

	for _, extractor := range e.networkRequest.Extractors {
		for match := range extractor.ExtractNetwork(replyStr) {
			if !extractor.Internal {
				extractorResults = append(extractorResults, match)
			}
		}
	}

	// Write a final string of output if matcher type is
	// AND or if we have extractors for the mechanism too.
	if len(e.networkRequest.Extractors) > 0 || matcherCondition == matchers.ANDCondition {
		e.writeOutputNetwork(reqURL, e.networkRequest.Payload, replyStr, nil, extractorResults)
		result.GotResults = true
	}
	return result
}

// Close closes the dns executer for a template.
func (e *NetworkExecuter) Close() {}
