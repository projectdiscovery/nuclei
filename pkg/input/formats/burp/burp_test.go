package burp

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/stretchr/testify/require"
)

func TestBurpParse(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/burp.xml"

	var gotMethodsToURLs []string

	err := format.Parse(proxifyInputFile, func(request *formats.RawRequest) bool {
		gotMethodsToURLs = append(gotMethodsToURLs, request.URL)
		return false
	})
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
}
