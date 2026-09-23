// Package katana implements an input format that ingests the JSONL output of
// the katana crawler (`katana -jsonl`) and turns each crawled endpoint into a
// fuzzable nuclei request. This bridges crawling and DAST: instead of fuzzing
// only a proxy-fed list of requests, nuclei can consume a crawl of the target
// directly, preserving method, headers, body and parameters discovered on the
// wire (including non-GET requests, which a bare URL list cannot express).
package katana

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// KatanaFormat is a parser for katana JSONL crawl output.
type KatanaFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new katana JSONL format parser.
func New() *KatanaFormat {
	return &KatanaFormat{}
}

var _ formats.Format = &KatanaFormat{}

// katanaResult mirrors the relevant subset of katana's output.Result JSON.
type katanaResult struct {
	Request *katanaRequest `json:"request"`
	Error   string         `json:"error"`
}

// katanaRequest mirrors the relevant subset of katana's navigation.Request JSON.
type katanaRequest struct {
	Method   string            `json:"method"`
	Endpoint string            `json:"endpoint"`
	Body     string            `json:"body"`
	Headers  map[string]string `json:"headers"`
	Raw      string            `json:"raw"`
}

// Name returns the name of the format.
func (k *KatanaFormat) Name() string {
	return "katana"
}

// SetOptions sets the options for the input format.
func (k *KatanaFormat) SetOptions(options formats.InputFormatOptions) {
	k.opts = options
}

// Parse parses katana JSONL output and calls the provided callback for each
// request it discovers. It is tolerant of mixed input: blank lines are skipped,
// and a bare URL line (katana's default non-JSONL output) is treated as a GET.
func (k *KatanaFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	reader := bufio.NewReader(input)
	for {
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("could not read katana jsonl input: %w", err)
		}

		line = strings.TrimSpace(line)
		if line != "" {
			if !strings.HasPrefix(line, "{") {
				// Bare URL line (katana default output without -jsonl): treat as GET.
				if isAbsoluteURL(line) {
					rr, err := k.buildFromComponents(http.MethodGet, line, nil, "")
					if err != nil {
						gologger.Warning().Msgf("katana: could not parse url %s: %s\n", line, err)
					} else if resultsCb(rr) {
						return nil
					}
				} else {
					gologger.Warning().Msg("katana: could not parse line as a URL or JSON record\n")
				}
			} else {
				var result katanaResult
				if err := json.Unmarshal([]byte(line), &result); err != nil {
					gologger.Warning().Msgf("katana: could not decode jsonl line: %s\n", err)
				} else if result.Request == nil || result.Request.Endpoint == "" {
					gologger.Warning().Msg("katana: invalid record with missing request or endpoint\n")
				} else {
					rr, err := k.toRequestResponse(result.Request)
					if err != nil {
						gologger.Warning().Msgf("katana: could not parse request %s: %s\n", result.Request.Endpoint, err)
					} else if resultsCb(rr) {
						return nil
					}
				}
			}
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

// toRequestResponse converts a katana request into nuclei's standard
// RequestResponse. It prefers the captured raw request when available and falls
// back to synthesizing one from the discovered components otherwise.
func (k *KatanaFormat) toRequestResponse(req *katanaRequest) (*types.RequestResponse, error) {
	if strings.TrimSpace(req.Raw) != "" {
		return types.ParseRawRequestWithURL(req.Raw, req.Endpoint)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	return k.buildFromComponents(method, req.Endpoint, req.Headers, req.Body)
}

// buildFromComponents synthesizes a raw HTTP request from discrete fields and
// parses it back into a RequestResponse, reusing the well-tested raw parser so
// the resulting object is identical in shape to the other input formats.
func (k *KatanaFormat) buildFromComponents(method, endpoint string, headers map[string]string, body string) (*types.RequestResponse, error) {
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint: %w", err)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("endpoint %q has no host", endpoint)
	}

	requestURI := parsed.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}

	var sb strings.Builder
	sb.WriteString(method)
	sb.WriteString(" ")
	sb.WriteString(requestURI)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: ")
	sb.WriteString(parsed.Host)
	sb.WriteString("\r\n")

	// Emit headers in a deterministic order, skipping Host (already written).
	for _, key := range sortedHeaderKeys(headers) {
		if strings.EqualFold(key, "Host") {
			continue
		}
		sb.WriteString(key)
		sb.WriteString(": ")
		sb.WriteString(headers[key])
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	if body != "" {
		sb.WriteString(body)
	}

	return types.ParseRawRequestWithURL(sb.String(), endpoint)
}

// sortedHeaderKeys returns the header keys in deterministic (sorted) order.
func sortedHeaderKeys(headers map[string]string) []string {
	if len(headers) == 0 {
		return nil
	}
	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// isAbsoluteURL reports whether the line is an absolute http(s) URL.
func isAbsoluteURL(line string) bool {
	u, err := url.Parse(line)
	return err == nil && u.IsAbs() && u.Host != "" && (u.Scheme == "http" || u.Scheme == "https")
}
