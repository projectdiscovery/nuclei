package fuzzing

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFuzzingAnalyzeRequest(t *testing.T) {
	req, err := http.NewRequest("GET", "http://example.com/command.php?url=http://google.com&b=test", nil)
	require.Nil(t, err, "could not create http request")
	req.Header.Set("User-Agent", "Test")
	req.Header.Set("X-WWW-URL", "http://www.google.com")
	normalized, err := NormalizeRequest(req)
	require.Nil(t, err, "could not create normalized request")

	options := &AnalyzerOptions{
		Replace: []string{"http://collaborator.pd.io/B215ADE3-D31E-40C4-95F1-AD32AAF3E832"},
		Parts:   []string{"default"},
		PartsConfig: map[string][]*AnalyzerPartsConfig{
			"all": []*AnalyzerPartsConfig{{Valid: &AnalyerPartsConfigMatcher{
				ValuesRegex: []string{"http.*"},
			}}},
		},
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
