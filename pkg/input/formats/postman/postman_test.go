package postman

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestPostmanParser(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/postman.json"

	var gotMethodsToURLs []string

	err := format.Parse(proxifyInputFile, func(rr *types.RequestResponse) bool {
		gotMethodsToURLs = append(gotMethodsToURLs, rr.URL.String())
		return false
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(gotMethodsToURLs) != 4 {
		t.Fatalf("invalid number of methods: %d", len(gotMethodsToURLs))
	}

	expectedURLs := []string{
		"http://127.0.0.1:8000/api/v1/search/",
		"http://127.0.0.1:8000/api/v1/search/?projectId=1,2",
		"http://127.0.0.1:8000/api/v1/search/?projectId=1,2&assetId=1,2",
		"http://127.0.0.1:8000/api/v1/search/",
	}
	require.ElementsMatch(t, gotMethodsToURLs, expectedURLs, "could not get swagger urls")
}
