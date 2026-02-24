package analyzers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestXSSContextAnalyzer_Analyze(t *testing.T) {
	analyzer := &XSSContextAnalyzer{}

	// Test table covering multiple HTML contexts
	tests := []struct {
		name          string
		responseBody  string
		expectedMatch bool
		expectedMsg   string
	}{
		{
			name:          "Text Node Reflection",
			responseBody:  "<div>%s</div>",
			expectedMatch: true,
			expectedMsg:   "text node",
		},
		{
			name:          "Attribute Reflection",
			responseBody:  "<input value='%s'>",
			expectedMatch: true,
			expectedMsg:   "attribute",
		},
		{
			name:          "HTML Comment Reflection",
			responseBody:  "",
			expectedMatch: true,
			expectedMsg:   "comment",
		},
		{
			name:          "No Reflection (Safe)",
			responseBody:  "<html><body>Safe Content</body></html>",
			expectedMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				val := r.URL.Query().Get("q")
				if tt.expectedMatch && tt.name != "No Reflection (Safe)" {
					fmt.Fprintf(w, tt.responseBody, val)
				} else {
					fmt.Fprint(w, tt.responseBody)
				}
			}))
			defer server.Close()

			opts := setupSeniorOptions(t, server.URL)
			matched, msg, err := analyzer.Analyze(opts)

			require.NoError(t, err)
			require.Equal(t, tt.expectedMatch, matched)
			if tt.expectedMatch {
				require.Contains(t, msg, tt.expectedMsg)
			}
			
			// Crucial verification of component state restoration
			require.Equal(t, "orig", opts.FuzzGenerated.Component.(*MockComponent).CurrentValue)
		})
	}
}

func setupSeniorOptions(t *testing.T, serverURL string) *Options {
	client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	req, err := retryablehttp.NewRequest(http.MethodGet, serverURL+"?q=orig", nil)
	require.NoError(t, err)
	
	return &Options{
		HttpClient: client,
		FuzzGenerated: fuzz.GeneratedRequest{
			Request: req, Value: "orig", Key: "q",
			Component: &MockComponent{URL: serverURL, Key: "q", CurrentValue: "orig"},
		},
	}
}

// MockComponent to emulate Nuclei's fuzzing engine behavior
type MockComponent struct {
	URL, Key, CurrentValue string
}

func (m *MockComponent) Name() string               { return "mock" }
func (m *MockComponent) SetValue(k, v string) error { if k == m.Key { m.CurrentValue = v }; return nil }
func (m *MockComponent) Rebuild() (*retryablehttp.Request, error) {
	u, _ := url.Parse(m.URL)
	q := u.Query()
	q.Set(m.Key, m.CurrentValue)
	u.RawQuery = q.Encode()
	return retryablehttp.NewRequest("GET", u.String(), nil)
}
func (m *MockComponent) Delete(k string) error                   { return nil }
func (m *MockComponent) Iterate(f func(string, any) error) error { return nil }
func (m *MockComponent) Parse(req *retryablehttp.Request) (bool, error) { return true, nil }
func (m *MockComponent) Clone() component.Component {
	return &MockComponent{URL: m.URL, Key: m.Key, CurrentValue: m.CurrentValue}
}