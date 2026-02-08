package xss

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/analyzers"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

// TestAnalyzerName verifies the analyzer name is correctly set
func TestAnalyzerName(t *testing.T) {
	analyzer := &Analyzer{}
	require.Equal(t, "xss_context", analyzer.Name())
}

// TestApplyInitialTransformation verifies payload transformations
func TestApplyInitialTransformation(t *testing.T) {
	analyzer := &Analyzer{}
	
	tests := []struct {
		name     string
		input    string
		contains []string
	}{
		{
			name:     "XSS_CANARY replacement",
			input:    "[XSS_CANARY]",
			contains: []string{"xss_", "<", ">", "'", "\"", "`"},
		},
		{
			name:     "Multiple placeholders",
			input:    "test=[XSS_CANARY]&num=[RANDNUM]",
			contains: []string{"xss_", "test=", "&num="},
		},
		{
			name:     "No transformation needed",
			input:    "plain_text",
			contains: []string{"plain_text"},
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.ApplyInitialTransformation(tt.input, nil)
			for _, expected := range tt.contains {
				require.Contains(t, result, expected)
			}
		})
	}
}

// TestDetectXSSContexts_HTMLTag tests detection of HTML tag context
func TestDetectXSSContexts_HTMLTag(t *testing.T) {
	analyzer := &Analyzer{}
	
	html := `<div>xss_1234_<>'"` + "`</div>"
	canary := "xss_1234_<>'\"``"
	
	contexts := analyzer.detectXSSContexts(html, canary)
	
	require.NotEmpty(t, contexts)
	require.Equal(t, "html_tag", contexts[0].Type)
	require.Contains(t, contexts[0].Payload, "<script>")
}

// TestDetectXSSContexts_AttributeQuoted tests detection of quoted attribute context
func TestDetectXSSContexts_AttributeQuoted(t *testing.T) {
	analyzer := &Analyzer{}
	
	html := `<input value="xss_1234_<>'"` + "`" + `">`
	canary := "xss_1234_<>'\"``"
	
	contexts := analyzer.detectXSSContexts(html, canary)
	
	require.NotEmpty(t, contexts)
	require.Equal(t, "attribute_quoted", contexts[0].Type)
	require.Contains(t, contexts[0].Payload, `">`)
}

// TestDetectXSSContexts_EventHandler tests detection of event handler context
func TestDetectXSSContexts_EventHandler(t *testing.T) {
	analyzer := &Analyzer{}
	
	html := `<img onclick="xss_1234_<>'"` + "`" + `">`
	canary := "xss_1234_<>'\"``"
	
	contexts := analyzer.detectXSSContexts(html, canary)
	
	require.NotEmpty(t, contexts)
	require.Equal(t, "event_handler", contexts[0].Type)
	require.Contains(t, contexts[0].Payload, "alert(1)")
}

// TestDetectXSSContexts_URLAttribute tests detection of URL attribute context
func TestDetectXSSContexts_URLAttribute(t *testing.T) {
	analyzer := &Analyzer{}
	
	html := `<a href="xss_1234_<>'"` + "`" + `">link</a>`
	canary := "xss_1234_<>'\"``"
	
	contexts := analyzer.detectXSSContexts(html, canary)
	
	require.NotEmpty(t, contexts)
	require.Equal(t, "url_attribute", contexts[0].Type)
	require.Contains(t, contexts[0].Payload, "javascript:")
}

// TestDetectXSSContexts_HTMLComment tests detection of HTML comment context
func TestDetectXSSContexts_HTMLComment(t *testing.T) {
	analyzer := &Analyzer{}
	
	html := `<!-- xss_1234_<>'"` + "` -->"
	canary := "xss_1234_<>'\"``"
	
	contexts := analyzer.detectXSSContexts(html, canary)
	
	require.NotEmpty(t, contexts)
	require.Equal(t, "html_comment", contexts[0].Type)
	require.Contains(t, contexts[0].Payload, "-->")
}

// TestDetectXSSContexts_StyleAttribute tests detection of style attribute context
func TestDetectXSSContexts_StyleAttribute(t *testing.T) {
	analyzer := &Analyzer{}
	
	html := `<div style="color: xss_1234_<>'"` + "`" + `">text</div>`
	canary := "xss_1234_<>'\"``"
	
	contexts := analyzer.detectXSSContexts(html, canary)
	
	require.NotEmpty(t, contexts)
	require.Equal(t, "style_attribute", contexts[0].Type)
}

// TestDetectFilters verifies filter detection logic
func TestDetectFilters(t *testing.T) {
	analyzer := &Analyzer{}
	
	tests := []struct {
		name     string
		text     string
		canary   string
		expected string
	}{
		{
			name:     "No filters",
			text:     "xss_1234_<>'\"``",
			canary:   "xss_1234_<>'\"``",
			expected: "none",
		},
		{
			name:     "HTML encoded",
			text:     "xss_1234_&lt;&gt;'\"``",
			canary:   "xss_1234_<>'\"``",
			expected: "html_encoded",
		},
		{
			name:     "Angle brackets filtered",
			text:     "xss_1234_'\"``",
			canary:   "xss_1234_<>'\"``",
			expected: "angle_brackets_filtered",
		},
		{
			name:     "Quotes escaped",
			text:     "xss_1234_<>\\'\\\"``",
			canary:   "xss_1234_<>'\"``",
			expected: "quotes_escaped",
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.detectFilters(tt.text, tt.canary)
			require.Contains(t, result, tt.expected)
		})
	}
}

// TestAnalyze_NoReflection tests behavior when canary is not reflected
func TestAnalyze_NoReflection(t *testing.T) {
	// Setup mock HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html><body>No reflection here</body></html>"))
	}))
	defer server.Close()
	
	// Setup analyzer options
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	
	mockComponent := &mockComponent{
		value: "",
	}
	
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			OriginalPayload: "[XSS_CANARY]",
			Key:             "q",
			Component:       mockComponent,
		},
		HttpClient:         client,
		AnalyzerParameters: nil,
	}
	
	analyzer := &Analyzer{}
	matched, reason, err := analyzer.Analyze(options)
	
	require.NoError(t, err)
	require.False(t, matched)
	require.Empty(t, reason)
}

// TestAnalyze_HTMLTagContext tests XSS detection in HTML tag context
func TestAnalyze_HTMLTagContext(t *testing.T) {
	// Setup mock HTTP server that reflects input in HTML context
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query().Get("q")
		if strings.Contains(query, "<script>alert(1)</script>") {
			// Exploit request - reflect unescaped
			w.Write([]byte("<html><body>" + query + "</body></html>"))
		} else {
			// Probe request - reflect canary
			w.Write([]byte("<html><body>" + query + "</body></html>"))
		}
	}))
	defer server.Close()
	
	// Setup analyzer options
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSpraying)
	
	mockComponent := &mockComponent{
		value:     "",
		serverURL: server.URL,
	}
	
	options := &analyzers.Options{
		FuzzGenerated: fuzz.GeneratedRequest{
			OriginalPayload: "[XSS_CANARY]",
			Key:             "q",
			Component:       mockComponent,
		},
		HttpClient:         client,
		AnalyzerParameters: nil,
	}
	
	analyzer := &Analyzer{}
	matched, reason, err := analyzer.Analyze(options)
	
	require.NoError(t, err)
	require.True(t, matched)
	require.Contains(t, reason, "XSS vulnerability confirmed")
	require.Contains(t, reason, "html_tag")
}

// TestVerifyExploitation tests various exploitation verification scenarios
func TestVerifyExploitation(t *testing.T) {
	analyzer := &Analyzer{}
	
	tests := []struct {
		name     string
		body     string
		context  XSSContext
		expected bool
	}{
		{
			name: "HTML tag context exploited",
			body: "<div><script>alert(1)</script></div>",
			context: XSSContext{
				Type:    "html_tag",
				Payload: "<script>alert(1)</script>",
			},
			expected: true,
		},
		{
			name: "Event handler context exploited",
			body: `<img onclick="alert(1)">`,
			context: XSSContext{
				Type:    "event_handler",
				Payload: "alert(1)",
			},
			expected: true,
		},
		{
			name: "URL attribute context exploited",
			body: `<a href="javascript:alert(1)">link</a>`,
			context: XSSContext{
				Type:    "url_attribute",
				Payload: "javascript:alert(1)",
			},
			expected: true,
		},
		{
			name: "Payload escaped - not exploited",
			body: `<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>`,
			context: XSSContext{
				Type:    "html_tag",
				Payload: "<script>alert(1)</script>",
			},
			expected: false,
		},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := analyzer.verifyExploitation(tt.body, tt.context)
			require.Equal(t, tt.expected, result)
		})
	}
}

// mockComponent implements the Component interface for testing
type mockComponent struct {
	value     string
	serverURL string
}

func (m *mockComponent) SetValue(key, value string) error {
	m.value = value
	return nil
}

func (m *mockComponent) Rebuild() (*retryablehttp.Request, error) {
	req, _ := retryablehttp.NewRequest("GET", m.serverURL+"?q="+m.value, nil)
	return req, nil
}

func (m *mockComponent) Clone() component.Component {
	return &mockComponent{
		value:     m.value,
		serverURL: m.serverURL,
	}
}

func (m *mockComponent) Name() string {
	return "mock"
}

func (m *mockComponent) Parse(req *retryablehttp.Request) (bool, error) {
	return true, nil
}

func (m *mockComponent) Iterate(fn func(key string, value interface{}) error) error {
	return fn("q", m.value)
}

func (m *mockComponent) Delete(key string) error {
	return nil
}
