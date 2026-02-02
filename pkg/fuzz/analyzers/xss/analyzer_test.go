package xss

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
)

func TestAnalyzerName(t *testing.T) {
	analyzer := &Analyzer{}
	if analyzer.Name() != AnalyzerName {
		t.Errorf("Expected name %s, got %s", AnalyzerName, analyzer.Name())
	}
}

func TestApplyInitialTransformation(t *testing.T) {
	analyzer := &Analyzer{}

	tests := []struct {
		name     string
		input    string
		params   map[string]interface{}
		expected string
	}{
		{
			name:     "Replace XSS_CANARY with default",
			input:    "test[XSS_CANARY]end",
			params:   map[string]interface{}{},
			expected: "test" + DefaultCanary + "end",
		},
		{
			name:  "Replace XSS_CANARY with custom",
			input: "test[XSS_CANARY]end",
			params: map[string]interface{}{
				"canary": "customCanary123",
			},
			expected: "testcustomCanary123end",
		},
		{
			name:     "No placeholder",
			input:    "testend",
			params:   map[string]interface{}{},
			expected: "testend",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.ApplyInitialTransformation(tt.input, tt.params)
			if result != tt.expected {
				t.Errorf("Expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestXSSAnalyzerHTMLBodyContext(t *testing.T) {
	// Create test server that reflects input without encoding
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		w.Write([]byte(fmt.Sprintf("<html><body><div>Search: %s</div></body></html>", param)))
	}))
	defer server.Close()

	// Create analyzer
	analyzer := &Analyzer{}

	// Create request
	req, err := retryablehttp.NewRequest("GET", server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Create component
	comp := &component.Query{}
	if _, err := comp.Parse(req); err != nil {
		t.Fatalf("Failed to parse component: %v", err)
	}

	// Create options
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:         req,
			Component:       comp,
			Key:             "q",
			OriginalPayload: DefaultCanary,
		},
		HttpClient:         client,
		AnalyzerParameters: map[string]interface{}{},
	}

	// Run analyzer
	matched, details, err := analyzer.Analyze(options)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !matched {
		t.Fatal("Expected XSS to be detected in HTML body context")
	}

	if details == "" {
		t.Error("Expected details to be provided")
	}

	// Check details contain expected information
	if !strings.Contains(details, "HTML_BODY") {
		t.Error("Expected details to mention HTML_BODY context")
	}
}

func TestXSSAnalyzerAttributeContext(t *testing.T) {
	// Create test server that reflects input in attribute
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		w.Write([]byte(fmt.Sprintf(`<input type="text" value="%s">`, param)))
	}))
	defer server.Close()

	// Create analyzer
	analyzer := &Analyzer{}

	// Create request
	req, err := retryablehttp.NewRequest("GET", server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Create component
	comp := &component.Query{}
	if _, err := comp.Parse(req); err != nil {
		t.Fatalf("Failed to parse component: %v", err)
	}

	// Create options
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:         req,
			Component:       comp,
			Key:             "q",
			OriginalPayload: DefaultCanary,
		},
		HttpClient:         client,
		AnalyzerParameters: map[string]interface{}{},
	}

	// Run analyzer
	matched, details, err := analyzer.Analyze(options)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !matched {
		t.Fatal("Expected XSS to be detected in attribute context")
	}

	if !strings.Contains(details, "ATTRIBUTE") {
		t.Error("Expected details to mention ATTRIBUTE context")
	}
}

func TestXSSAnalyzerNoReflection(t *testing.T) {
	// Create test server that doesn't reflect input
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>Static content</body></html>"))
	}))
	defer server.Close()

	// Create analyzer
	analyzer := &Analyzer{}

	// Create request
	req, err := retryablehttp.NewRequest("GET", server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Create component
	comp := &component.Query{}
	if _, err := comp.Parse(req); err != nil {
		t.Fatalf("Failed to parse component: %v", err)
	}

	// Create options
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:         req,
			Component:       comp,
			Key:             "q",
			OriginalPayload: DefaultCanary,
		},
		HttpClient:         client,
		AnalyzerParameters: map[string]interface{}{},
	}

	// Run analyzer
	matched, _, err := analyzer.Analyze(options)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if matched {
		t.Fatal("Expected no XSS detection when input is not reflected")
	}
}

func TestXSSAnalyzerEncodedReflection(t *testing.T) {
	// Create test server that encodes special characters
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		// Encode < > " ' characters
		param = html.EscapeString(param)
		w.Write([]byte(fmt.Sprintf("<html><body><div>Search: %s</div></body></html>", param)))
	}))
	defer server.Close()

	// Create analyzer
	analyzer := &Analyzer{}

	// Create request
	req, err := retryablehttp.NewRequest("GET", server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Create component
	comp := &component.Query{}
	if _, err := comp.Parse(req); err != nil {
		t.Fatalf("Failed to parse component: %v", err)
	}

	// Create options
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:         req,
			Component:       comp,
			Key:             "q",
			OriginalPayload: DefaultCanary,
		},
		HttpClient:         client,
		AnalyzerParameters: map[string]interface{}{},
	}

	// Run analyzer
	matched, _, err := analyzer.Analyze(options)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should not match since special chars are encoded
	if matched {
		t.Fatal("Expected no XSS detection when special characters are encoded")
	}
}

func TestXSSAnalyzerScriptContext(t *testing.T) {
	// Create test server that reflects input in script block
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		w.Write([]byte(fmt.Sprintf(`<script>var search = "%s";</script>`, param)))
	}))
	defer server.Close()

	// Create analyzer
	analyzer := &Analyzer{}

	// Create request
	req, err := retryablehttp.NewRequest("GET", server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Create component
	comp := &component.Query{}
	if _, err := comp.Parse(req); err != nil {
		t.Fatalf("Failed to parse component: %v", err)
	}

	// Create options
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:         req,
			Component:       comp,
			Key:             "q",
			OriginalPayload: DefaultCanary,
		},
		HttpClient:         client,
		AnalyzerParameters: map[string]interface{}{},
	}

	// Run analyzer
	matched, details, err := analyzer.Analyze(options)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !matched {
		t.Fatal("Expected XSS to be detected in script context")
	}

	if !strings.Contains(details, "SCRIPT") {
		t.Error("Expected details to mention SCRIPT context")
	}
}

func TestXSSAnalyzerWithCustomCanary(t *testing.T) {
	// Create test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		w.Write([]byte(fmt.Sprintf("<div>%s</div>", param)))
	}))
	defer server.Close()

	// Create analyzer
	analyzer := &Analyzer{}

	customCanary := "myCustomCanary123"

	// Create request
	req, err := retryablehttp.NewRequest("GET", server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Create component
	comp := &component.Query{}
	if _, err := comp.Parse(req); err != nil {
		t.Fatalf("Failed to parse component: %v", err)
	}

	// Create options with custom canary
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:         req,
			Component:       comp,
			Key:             "q",
			OriginalPayload: customCanary,
		},
		HttpClient: client,
		AnalyzerParameters: map[string]interface{}{
			"canary": customCanary,
		},
	}

	// Run analyzer
	matched, details, err := analyzer.Analyze(options)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !matched {
		t.Fatal("Expected XSS to be detected with custom canary")
	}

	if !strings.Contains(details, customCanary) {
		t.Errorf("Expected details to mention custom canary %q", customCanary)
	}
}

func TestXSSAnalyzerURLAttributeContext(t *testing.T) {
	// Create test server that reflects input in href attribute
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		w.Write([]byte(fmt.Sprintf(`<a href="%s">click</a>`, param)))
	}))
	defer server.Close()

	analyzer := &Analyzer{}

	req, err := retryablehttp.NewRequest("GET", server.URL+"?q=test", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	comp := &component.Query{}
	if _, err := comp.Parse(req); err != nil {
		t.Fatalf("Failed to parse component: %v", err)
	}

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:         req,
			Component:       comp,
			Key:             "q",
			OriginalPayload: DefaultCanary,
		},
		HttpClient:         client,
		AnalyzerParameters: map[string]interface{}{},
	}

	// Run analyzer
	matched, details, err := analyzer.Analyze(options)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	if !matched {
		t.Fatal("Expected XSS to be detected in URL attribute context")
	}

	if !strings.Contains(details, "URL") {
		t.Error("Expected details to mention URL context")
	}
}

func TestXSSAnalyzerFalsePositiveInComment(t *testing.T) {
	// Server reflects payload but wraps it in HTML comment
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		param := r.URL.Query().Get("q")
		w.Write([]byte(fmt.Sprintf("<!-- %s -->", param)))
	}))
	defer server.Close()

	analyzer := &Analyzer{}

	req, _ := retryablehttp.NewRequest("GET", server.URL+"?q=test", nil)
	comp := &component.Query{}
	comp.Parse(req)

	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			Request:         req,
			Component:       comp,
			Key:             "q",
			OriginalPayload: DefaultCanary,
		},
		HttpClient:         client,
		AnalyzerParameters: map[string]interface{}{},
	}

	// Run analyzer
	matched, _, err := analyzer.Analyze(options)

	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}

	// Should NOT match since payload is in comment (not exploitable)
	if matched {
		t.Fatal("Expected no XSS detection when payload is in HTML comment")
	}
}
