package fuzzing

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestFuzzingAnalyzeRequest(t *testing.T) {
	req, err := http.NewRequest("POST", "http://example.com/test-1?fuzz=abc", strings.NewReader(`
	{
		"name": {"first": "Tom", "last": "Anderson"},
		"children": ["Sara"]
	}`))
	require.Nil(t, err, "could not create http request")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Length", "1")

	newReq, err := retryablehttp.FromRequest(req)
	require.Nil(t, err, "could not create http request")

	normalized, err := NormalizeRequest(newReq)
	require.Nil(t, err, "could not create normalized request")

	options := &AnalyzerOptions{
		Append:      []string{"'-sleep(10)-'"},
		Parts:       []string{"headers"},
		PartsConfig: map[string][]*AnalyzerPartsConfig{},
	}
	err = options.Compile()
	require.Nil(t, err, "could not compile regex request")

	err = AnalyzeRequest(normalized, options, func(req *http.Request) {
		if data, err := httputil.DumpRequestOut(req, true); err == nil {
			fmt.Printf("%v\n", string(data))
		}
	})
	require.Nil(t, err, "could not analyze normalized request")
}
