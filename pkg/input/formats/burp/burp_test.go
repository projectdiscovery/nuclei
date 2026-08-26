package burp

import (
	"os"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestBurpParse(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/burp.xml"

	var gotMethodsToURLs []string
	var gotResponses int

	file, err := os.Open(proxifyInputFile)
	require.Nilf(t, err, "error opening proxify input file: %v", err)
	defer func() {
		_ = file.Close()
	}()

	err = format.Parse(file, func(request *types.RequestResponse) bool {
		gotMethodsToURLs = append(gotMethodsToURLs, request.URL.String())
		if request.Response != nil && request.Response.Raw != "" {
			gotResponses++
			require.Contains(t, request.Response.Raw, "HTTP/")
		}
		return false
	}, proxifyInputFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(gotMethodsToURLs) != 2 {
		t.Fatalf("invalid number of methods: %d", len(gotMethodsToURLs))
	}
	var expectedURLs = []string{
		"http://localhost:8087/scans",
		"http://google.com/",
	}
	require.ElementsMatch(t, expectedURLs, gotMethodsToURLs, "could not get burp urls")
	require.Equal(t, 2, gotResponses, "burp items should include response bodies for passive mode")
}

func TestBurpParseResponseBodyContent(t *testing.T) {
	format := New()
	file, err := os.Open("../testdata/burp.xml")
	require.NoError(t, err)
	defer func() { _ = file.Close() }()

	var first *types.RequestResponse
	err = format.Parse(file, func(request *types.RequestResponse) bool {
		if first == nil {
			first = request
		}
		return false
	}, "../testdata/burp.xml")
	require.NoError(t, err)
	require.NotNil(t, first)
	require.NotNil(t, first.Response)
	require.Contains(t, first.Response.Raw, `"id":"1"`)
	require.Contains(t, first.Request.Raw, "POST /scans")
}
