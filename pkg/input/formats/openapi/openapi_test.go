package openapi

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
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

	err := format.Parse(proxifyInputFile, func(request *formats.RawRequest) bool {
		gotMethodsToURLs[request.Method] = append(gotMethodsToURLs[request.Method],
			strings.Replace(request.URL, baseURL, "{{baseUrl}}", 1))
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
