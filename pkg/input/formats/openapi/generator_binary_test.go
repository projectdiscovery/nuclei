package openapi

import (
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/stretchr/testify/require"
)

func TestOpenAPIOctetStreamContentType(t *testing.T) {
	tests := []struct {
		name        string
		schema      string
		contentType string
	}{
		{name: "binary format", schema: "{type: string, format: binary}", contentType: "application/octet-stream"},
		{name: "byte format", schema: "{type: string, format: byte}", contentType: "application/octet-stream"},
		{name: "plain string", schema: "{type: string}", contentType: "text/plain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := `openapi: 3.0.0
info: {title: t, version: "1"}
servers: [{url: "http://example.com"}]
paths:
  /upload:
    post:
      requestBody:
        content:
          application/octet-stream: {schema: ` + tt.schema + `}
      responses:
        "200": {description: ok}
`
			var contentTypes []string
			err := New().Parse(strings.NewReader(spec), func(rr *types.RequestResponse) bool {
				value, _ := rr.Request.Headers.Get("Content-Type")
				contentTypes = append(contentTypes, value)
				return false
			}, "spec.yaml")
			require.NoError(t, err)
			require.Equal(t, []string{tt.contentType}, contentTypes)
		})
	}
}
