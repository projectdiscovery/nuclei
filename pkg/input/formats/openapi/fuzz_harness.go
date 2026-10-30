package openapi

import (
	"bytes"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
)

const fuzzMaxInputSize = 64 << 10

// fuzzOpenAPIParsing feeds data to the OpenAPI format parser as a raw schema
// document and drives request generation. It must never panic for any input;
// it returns true when the schema parsed and at least one request was produced.
func fuzzOpenAPIParsing(data []byte) bool {
	if len(data) == 0 || len(data) > fuzzMaxInputSize {
		return false
	}

	format := New()
	format.SetOptions(formats.InputFormatOptions{})

	produced := false
	cb := func(rr *types.RequestResponse) bool {
		produced = true
		return true
	}
	if err := format.Parse(bytes.NewReader(data), cb, "fuzz.openapi"); err != nil {
		return false
	}
	return produced
}
