package swagger

import (
	"os"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestSwaggerAPIParser(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/swagger.yaml"

	var gotMethodsToURLs []string

	file, err := os.Open(proxifyInputFile)
	require.Nilf(t, err, "error opening proxify input file: %v", err)
	defer func() {
		_ = file.Close()
	}()

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

func TestSwaggerParseNullEntries(t *testing.T) {
	// Each spec has a null map value or list item that decodes to a nil
	// pointer and used to panic inside openapi2conv.ToV3.
	specs := map[string]string{
		"null-path-item": `
swagger: "2.0"
info: {title: t, version: "1"}
host: localhost
paths:
  /x:
`,
		"null-parameter": `
swagger: "2.0"
info: {title: t, version: "1"}
host: localhost
paths:
  /x:
    get:
      parameters:
        -
      responses: {"200": {description: ok}}
`,
		"null-response": `
swagger: "2.0"
info: {title: t, version: "1"}
host: localhost
paths:
  /x:
    get:
      responses: {"200": }
`,
		"null-response-header": `
swagger: "2.0"
info: {title: t, version: "1"}
host: localhost
responses:
  Shared:
    description: ok
    headers:
      X-Shared:
paths:
  /x:
    get:
      responses:
        "200":
          description: ok
          headers:
            X-Rate-Limit:
`,
	}

	for name, spec := range specs {
		t.Run(name, func(t *testing.T) {
			var count int
			err := New().Parse(strings.NewReader(spec), func(request *types.RequestResponse) bool {
				count++
				return false
			}, "spec.yaml")
			require.NoError(t, err)
			if name != "null-path-item" {
				require.Equal(t, 1, count, "the operation should still produce a request")
			}
		})
	}
}

func TestSwaggerParseOversizeInput(t *testing.T) {
	origLimit := formats.MaxSpecFileSize
	formats.MaxSpecFileSize = 64
	defer func() {
		formats.MaxSpecFileSize = origLimit
	}()

	oversizedYAML := strings.Repeat("# padding comments\n", 10) + "swagger: \"2.0\"\ninfo: {title: t, version: \"1\"}\n"
	err := New().Parse(strings.NewReader(oversizedYAML), func(request *types.RequestResponse) bool {
		return false
	}, "spec.yaml")
	require.Error(t, err)
	require.Contains(t, err.Error(), "exceeds maximum allowed limit")
}
