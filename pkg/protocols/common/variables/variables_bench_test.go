package variables

import (
	"fmt"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

func BenchmarkVariableEvaluate(b *testing.B) {
	// Setup variables with chained references and DSL functions
	variables := &Variable{
		LazyEval:                  true,
		InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(5),
	}
	variables.Set("base", "testvalue")
	variables.Set("derived1", "{{base}}_suffix")
	variables.Set("derived2", "{{md5(derived1)}}")
	variables.Set("derived3", "prefix_{{derived2}}")
	variables.Set("final", "{{derived3}}_end")

	inputValues := map[string]interface{}{
		"BaseURL": "http://example.com",
		"Host":    "example.com",
		"Path":    "/api/v1",
	}

	b.Run("Evaluate", func(b *testing.B) {
		b.Run("5Variables", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = variables.Evaluate(inputValues)
			}
		})

		b.Run("Parallel", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					_ = variables.Evaluate(inputValues)
				}
			})
		})
	})
}

func BenchmarkVariableEvaluateScaling(b *testing.B) {
	// Test how the optimization scales with different variable counts
	inputValues := map[string]interface{}{
		"BaseURL": "http://example.com",
		"Host":    "example.com",
	}

	benchmarkSizes := []int{1, 5, 10, 20}

	for _, size := range benchmarkSizes {
		variables := &Variable{
			LazyEval:                  true,
			InsertionOrderedStringMap: *utils.NewEmptyInsertionOrderedStringMap(size),
		}

		// Create chain of variables
		for i := range size {
			varName := fmt.Sprintf("var%d", i)
			if i == 0 {
				variables.Set(varName, "initial")
			} else {
				prevVarName := fmt.Sprintf("var%d", i-1)
				variables.Set(varName, fmt.Sprintf("{{%s}}_step", prevVarName))
			}
		}

		b.Run(fmt.Sprintf("Variables-%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				_ = variables.Evaluate(inputValues)
			}
		})
	}
}
