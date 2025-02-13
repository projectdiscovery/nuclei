package openapi

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

const baseURL = "http://hackthebox:5000"

var methodToURLs = map[string][]string{
	"GET": {
		"{{baseUrl}}/createdb",
		"{{baseUrl}}/",
		"{{baseUrl}}/users/v1/John.Doe",
		"{{baseUrl}}/users/v1",
		"{{baseUrl}}/users/v1/_debug",
		"{{baseUrl}}/books/v1",
		"{{baseUrl}}/books/v1/bookTitle77",
	},
	"POST": {
		"{{baseUrl}}/users/v1/register",
		"{{baseUrl}}/users/v1/login",
		"{{baseUrl}}/books/v1",
	},
	"PUT": {
		"{{baseUrl}}/users/v1/name1/email",
		"{{baseUrl}}/users/v1/name1/password",
	},
	"DELETE": {
		"{{baseUrl}}/users/v1/name1",
	},
}

func TestOpenAPIParser(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/openapi.yaml"

	gotMethodsToURLs := make(map[string][]string)

	file, err := os.Open(proxifyInputFile)
	require.Nilf(t, err, "error opening proxify input file: %v", err)
	defer file.Close()

	err = format.Parse(file, func(rr *types.RequestResponse) bool {
		gotMethodsToURLs[rr.Request.Method] = append(gotMethodsToURLs[rr.Request.Method],
			strings.Replace(rr.URL.String(), baseURL, "{{baseUrl}}", 1))
		return false
	}, proxifyInputFile)
	if err != nil {
		t.Fatal(err)
	}

	if len(gotMethodsToURLs) != len(methodToURLs) {
		t.Fatalf("invalid number of methods: %d", len(gotMethodsToURLs))
	}

	for method, urls := range gotMethodsToURLs {
		if len(urls) != len(methodToURLs[method]) {
			t.Fatalf("invalid number of urls for method %s: %d", method, len(urls))
		}
		require.ElementsMatch(t, urls, methodToURLs[method], "invalid urls for method %s", method)
	}
}
