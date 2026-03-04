package xss

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"

	"golang.org/x/net/html"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
)

// Analyzer implements XSS context analysis for fuzzing payloads.
type Analyzer struct {
	canary string
}

func init() {
	analyzers.RegisterAnalyzer("xss_context", &Analyzer{})
}

// Name returns the unique name for this analyzer.
func (a *Analyzer) Name() string {
	return "xss_context"
}

// ApplyInitialTransformation injects the XSS canary into the payload.
func (a *Analyzer) ApplyInitialTransformation(payload string) string {
	if a.canary == "" {
		a.canary = generateCanary()
	}
	return strings.ReplaceAll(payload, "[XSS_CANARY]", a.canary)
}

func generateCanary() string {
	// Canary includes characters that often get filtered or encoded
	return "<XSScan>\"'</XSScan>"
}

// Analyze sends the transformed request, reads up to 10 MiB, and uses the HTML tokenizer
to find reflections in text, attributes, comments, or event handlers.
func (a *Analyzer) Analyze(opts *fuzz.Options, req *fuzz.Request) (*fuzz.Result, error) {
	if opts.HttpClient == nil {
		return nil, errors.New("nil HttpClient")
	}
	// Expand payload placeholders (RANDNUM, etc.)
	transformed, err := opts.ApplyPayloadTransform(req.Payload)
	if err != nil {
		return nil, err
	}
	// Create new request with transformed payload
	httpReq := req.Request.Clone(req.Request.Context())
	httpReq.Body = io.NopCloser(strings.NewReader(transformed))
	resp, err := opts.HttpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	// Cap body read to prevent memory exhaustion
	limited := io.LimitReader(resp.Body, 10<<20)
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, limited); err != nil {
		return nil, err
	}
	// Parse and look for canary reflections
	tok := html.NewTokenizer(bytes.NewReader(buf.Bytes()))
	for {
		t := tok.Next()
		switch t {
		case html.ErrorToken:
			if tok.Err() == io.EOF {
				return &fuzz.Result{Vulnerable: false}, nil
			}
			return nil, tok.Err()
		case html.TextToken:
			if strings.Contains(string(tok.Text()), a.canary) {
				return &fuzz.Result{Vulnerable: true, Details: "reflected in HTML text"}, nil
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			tokn := tok.Token()
			for _, attr := range tokn.Attr {
				if strings.Contains(attr.Val, a.canary) {
					key := strings.ToLower(attr.Key)
					if strings.HasPrefix(key, "on") {
						return &fuzz.Result{Vulnerable: true, Details: "reflected in event handler"}, nil
					}
					return &fuzz.Result{Vulnerable: true, Details: "reflected in attribute"}, nil
				}
			}
		case html.CommentToken:
			if strings.Contains(string(tok.Text()), a.canary) {
				return &fuzz.Result{Vulnerable: true, Details: "reflected in comment"}, nil
			}
		}
	}
}
