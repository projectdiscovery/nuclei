package openapi

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/formats"
)

func TestJSONFormatterParse(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/openapi.yaml"

	var urls []string
	err := format.Parse(proxifyInputFile, func(request *formats.RawRequest) bool {
		fmt.Printf("%+v\n", request)
		return false
	})
	if err != nil {
		t.Fatal(err)
	}

	_ = urls
}
