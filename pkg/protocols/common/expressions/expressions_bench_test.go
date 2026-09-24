package expressions

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func BenchmarkEvaluatePureDSL(b *testing.B) {
	values := map[string]interface{}{"name": "EXAMPLE"}
	for _, item := range []struct {
		name    string
		options *types.Options
	}{
		{name: "without scan options"},
		{name: "with scan options", options: &types.Options{RestrictLocalNetworkAccess: true}},
	} {
		b.Run(item.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				result, err := EvaluateWithOptions(`{{concat(to_lower(name), '-', hex_encode('abc'))}}`, values, item.options)
				if err != nil || result != "example-616263" {
					b.Fatalf("unexpected expression result %q: %v", result, err)
				}
			}
		})
	}
}
