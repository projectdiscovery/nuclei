// Package katana implements an input format that ingests the JSONL output of
// the katana crawler (`katana -jsonl`) and turns each crawled endpoint into a
// fuzzable nuclei request. This bridges crawling and DAST: instead of fuzzing
// only a proxy-fed list of requests, nuclei can consume a crawl of the target
// directly, preserving method, headers, body and parameters discovered on the
// wire (including non-GET requests, which a bare URL list cannot express).
package katana

import (
	"bufio"
	"bytes"
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

const (
	// MaxRecordSize is the maximum size of a single katana JSONL record. Crawled
	// requests can carry large bodies and raw dumps, so the limit sits well above
	// the 10MB of a realistic worst case record, while still bounding the memory a
	// single record can consume. Records above it are skipped, not buffered.
	MaxRecordSize = 32 * 1024 * 1024

	// readBufferSize is the size of the chunks a record is read in. An oversized or
	// unterminated record is drained through this buffer, so the memory used while
	// skipping it stays constant regardless of how long the record is.
	readBufferSize = 64 * 1024
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
// Records above MaxRecordSize are dropped with a warning so that a malformed or
// unterminated record cannot exhaust memory.
func (k *KatanaFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	reader := bufio.NewReaderSize(input, readBufferSize)
	for {
		record, oversized, err := readRecord(reader)
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("could not read katana jsonl input: %w", err)
		}

		if oversized {
			gologger.Warning().Msgf("katana: skipping record larger than %d bytes\n", MaxRecordSize)
		} else if len(record) > 0 && k.handleRecord(record, resultsCb) {
			return nil
		}

		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

// readRecord reads a single newline delimited record, keeping at most
// MaxRecordSize bytes in memory. A record above the limit is drained chunk by
// chunk and reported as oversized so the caller can skip it, instead of being
// accumulated in full.
func readRecord(reader *bufio.Reader) (record []byte, oversized bool, err error) {
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(chunk) > 0 {
			// The delimiter is trimmed off the record, so it does not count
			// towards the limit.
			size := len(chunk)
			if chunk[size-1] == '\n' {
				size--
			}
			if oversized || len(record)+size > MaxRecordSize {
				// Release what was read so far and keep consuming until the record
				// ends: only the reader buffer stays allocated while draining.
				oversized, record = true, nil
			} else {
				record = append(record, chunk...)
			}
		}
		// A full buffer without a delimiter means the record continues.
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return bytes.TrimSpace(record), oversized, err
	}
}

// handleRecord parses a single record and reports whether the callback asked to
// stop parsing.
func (k *KatanaFormat) handleRecord(record []byte, resultsCb formats.ParseReqRespCallback) bool {
	if record[0] != '{' {
		// Bare URL line (katana default output without -jsonl): treat as GET.
		line := string(record)
		if !isAbsoluteURL(line) {
			gologger.Warning().Msg("katana: could not parse line as a URL or JSON record\n")
			return false
		}
		rr, err := k.buildFromComponents(http.MethodGet, line, nil, "")
		if err != nil {
			gologger.Warning().Msgf("katana: could not parse url %s: %s\n", line, err)
			return false
		}
		return resultsCb(rr)
	}

	var result katanaResult
	if err := json.Unmarshal(record, &result); err != nil {
		gologger.Warning().Msgf("katana: could not decode jsonl line: %s\n", err)
		return false
	}
	if result.Request == nil || result.Request.Endpoint == "" {
		gologger.Warning().Msg("katana: invalid record with missing request or endpoint\n")
		return false
	}
	rr, err := k.toRequestResponse(result.Request)
	if err != nil {
		gologger.Warning().Msgf("katana: could not parse request %s: %s\n", result.Request.Endpoint, err)
		return false
	}
	return resultsCb(rr)
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
