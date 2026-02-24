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

	t.Run("reflection-in-text-node", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "<div>%s</div>", r.URL.Query().Get("q"))
		}))
		defer server.Close()
		runTest(t, analyzer, server.URL, "text node")
	})

	t.Run("reflection-in-attribute", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "<input value='%s'>", r.URL.Query().Get("q"))
		}))
		defer server.Close()
		runTest(t, analyzer, server.URL, "attribute")
	})

	t.Run("no-reflection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, "<html>safe content</html>")
		}))
		defer server.Close()
		
		opts := setupOptions(t, server.URL)
		matched, _, err := analyzer.Analyze(opts)
		require.NoError(t, err)
		require.False(t, matched)
	})
}

func setupOptions(t *testing.T, serverURL string) *Options {
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

func runTest(t *testing.T, analyzer *XSSContextAnalyzer, url string, expectedMsg string) {
	opts := setupOptions(t, url)
	matched, message, err := analyzer.Analyze(opts)
	require.NoError(t, err)
	require.True(t, matched)
	require.Contains(t, message, expectedMsg)
	require.Equal(t, "orig", opts.FuzzGenerated.Component.(*MockComponent).CurrentValue)
}

type MockComponent struct {
	URL, Key, CurrentValue string
}

func (m *MockComponent) Name() string { return "mock" }
func (m *MockComponent) SetValue(k, v string) error {
	if k == m.Key { m.CurrentValue = v }
	return nil
}
func (m *MockComponent) Rebuild() (*retryablehttp.Request, error) {
	params := url.Values{}
	params.Set(m.Key, m.CurrentValue)
	return retryablehttp.NewRequest("GET", m.URL+"?"+params.Encode(), nil)
}
func (m *MockComponent) Delete(k string) error { return nil }
func (m *MockComponent) Clone() component.Component { return &MockComponent{URL: m.URL, Key: m.Key, CurrentValue: m.CurrentValue} }
func (m *MockComponent) Parse(req *retryablehttp.Request) (bool, error) { return true, nil }
func (m *MockComponent) Iterate(f func(string, any) error) error { return nil }