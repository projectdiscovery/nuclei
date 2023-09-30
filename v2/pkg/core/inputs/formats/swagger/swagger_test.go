package swagger

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/formats"
	"github.com/stretchr/testify/require"
)

func TestSwagger(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/swagger.yaml"

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

	expectedURLs := []string{
		"https://localhost/users",
		"https://localhost/users/1?test=asc",
	}
	require.ElementsMatch(t, gotMethodsToURLs, expectedURLs, "could not get swagger urls")
}
