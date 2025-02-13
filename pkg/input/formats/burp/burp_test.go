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

	file, err := os.Open(proxifyInputFile)
	require.Nilf(t, err, "error opening proxify input file: %v", err)
	defer file.Close()

	err = format.Parse(file, func(request *types.RequestResponse) bool {
		gotMethodsToURLs = append(gotMethodsToURLs, request.URL.String())
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
}
