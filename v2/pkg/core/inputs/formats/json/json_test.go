package json

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/formats"
)

func TestJSONFormatterParse(t *testing.T) {
	format := New()

	proxifyInputFile := "../testdata/ginandjuice.proxify.json"

	err := format.Parse(proxifyInputFile, func(request *formats.RawRequest) bool {
		json.NewEncoder(os.Stdout).Encode(request)
		return false
	})
	if err != nil {
		t.Fatal(err)
	}
}
