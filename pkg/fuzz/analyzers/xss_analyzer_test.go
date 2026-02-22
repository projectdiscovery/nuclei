package analyzers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz"
	"github.com/projectdiscovery/nuclei/v3/pkg/fuzz/component"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestXSSContextAnalyzer_Analyze(t *testing.T) {
	analyzer := &XSSContextAnalyzer{}

	t.Run("reflection-in-text-node", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			val := r.URL.Query().Get("q")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, "<html><body><div>%s</div></body></html>", val)
		}))
		defer server.Close()

		client := retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
		req, _ := retryablehttp.NewRequest(http.MethodGet, server.URL+"?q=orig", nil)
		
		opts := &Options{
			HttpClient: client,
			FuzzGenerated: fuzz.GeneratedRequest{
				Request: req,
				Value:   "orig",
				Key:     "q",
				Component: &MockComponent{URL: server.URL, Key: "q", CurrentValue: "orig"},
			},
		}

		matched, message, err := analyzer.Analyze(opts)
		require.NoError(t, err)
		require.True(t, matched)
		require.Contains(t, message, "text node")
		// Verify restoration
		require.Equal(t, "orig", opts.FuzzGenerated.Component.(*MockComponent).CurrentValue)
	})
}

type MockComponent struct {
	URL          string
	Key          string
	CurrentValue string
}

func (m *MockComponent) Name() string { return "mock" }
func (m *MockComponent) SetValue(k, v string) error {
	if k == m.Key { m.CurrentValue = v }
	return nil
}
func (m *MockComponent) Delete(k string) error { return nil }
func (m *MockComponent) Clone() component.Component {
	return &MockComponent{URL: m.URL, Key: m.Key, CurrentValue: m.CurrentValue}
}
func (m *MockComponent) Rebuild() (*retryablehttp.Request, error) {
	return retryablehttp.NewRequest("GET", fmt.Sprintf("%s?%s=%s", m.URL, m.Key, m.CurrentValue), nil)
}
func (m *MockComponent) Parse(req *retryablehttp.Request) (bool, error) { return true, nil }
func (m *MockComponent) Iterate(f func(string, any) error) error       { return nil }