package generators

import (
	"testing"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func BenchmarkBuildPayloadFromOptions(b *testing.B) {
	// Setup options with vars and env vars
	vars := goflags.RuntimeMap{}
	_ = vars.Set("key1=value1")
	_ = vars.Set("key2=value2")
	_ = vars.Set("key3=value3")
	_ = vars.Set("key4=value4")
	_ = vars.Set("key5=value5")

	opts := &types.Options{
		Vars:                 vars,
		EnvironmentVariables: true, // This adds more entries
	}

	b.Run("Sequential", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = BuildPayloadFromOptions(opts)
		}
	})

	b.Run("Parallel", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				m := BuildPayloadFromOptions(opts)
				// Simulate typical usage - read a value
				_ = m["key1"]
			}
		})
	})
}
