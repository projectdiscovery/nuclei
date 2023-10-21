package openapi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/core/inputs/formats"
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

func TestJSONFormatterParse(t *testing.T) {
	t.Skipf("Skipping test no test data available")
	format := New()

	proxifyInputFile := "../testdata/aurora.yaml"

	gotMethodsToURLs := make(map[string][]string)

	err := format.Parse(proxifyInputFile, func(request *formats.RawRequest) bool {
		gotMethodsToURLs[request.Method] = append(gotMethodsToURLs[request.Method],
			strings.Replace(request.URL, baseURL, "{{baseUrl}}", 1))
		fmt.Printf("%v\n\n", request.Raw)
		return false
	})
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
