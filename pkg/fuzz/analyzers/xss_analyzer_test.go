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

	t.Run("text-context-detection", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "<html><body><div>pd_xss</div></body></html>")
		}))
		defer server.Close()

		req, _ := retryablehttp.NewRequest(http.MethodGet, server.URL, nil)
		client := retryablehttp.NewClient(retryablehttp.Options{})

		opts := &Options{
			HttpClient: client,
			FuzzGenerated: fuzz.GeneratedRequest{
				Request:         req,
				OriginalPayload: "",
				Key:             "query",
				Component:       &MockComponent{URL: server.URL},
			},
		}

		matched, message, err := analyzer.Analyze(opts)
		require.NoError(t, err)
		require.True(t, matched)
		require.Contains(t, message, "text:")
	})
}

type MockComponent struct{ URL string }
func (m *MockComponent) Name() string { return "mock" }
func (m *MockComponent) SetValue(k, v string) error { return nil }
func (m *MockComponent) Delete(k string) error { return nil }
func (m *MockComponent) GetValue(k string) (string, bool) { return "", false }
func (m *MockComponent) Clone() component.Component { return m }
func (m *MockComponent) Value() any { return nil }
func (m *MockComponent) Rebuild() (*retryablehttp.Request, error) {
	return retryablehttp.NewRequest("GET", m.URL, nil)
}
func (m *MockComponent) Parse(req *retryablehttp.Request) (bool, error) { return true, nil }
func (m *MockComponent) Iterate(f func(string, any) error) error { return nil }
func (m *MockComponent) Fetch(f func(string, any) bool) error { return nil }
func (m *MockComponent) Type() any { return nil }