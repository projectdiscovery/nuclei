package flow_test

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/flow"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func BenchmarkGetJSRuntime(b *testing.B) {
	opts := types.DefaultOptions()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		runtime := flow.GetJSRuntime(opts)
		flow.PutJSRuntime(runtime)
	}
}
