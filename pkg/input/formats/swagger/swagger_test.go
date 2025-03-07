package swagger

import (
	"os"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestSwaggerAPIParser(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/swagger.yaml"

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

	expectedURLs := []string{
		"https://localhost/v1/users",
		"https://localhost/v1/users/1?test=asc",
	}
	require.ElementsMatch(t, gotMethodsToURLs, expectedURLs, "could not get swagger urls")
}
