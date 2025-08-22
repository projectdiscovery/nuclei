package exprcache

import (
	"testing"

	"github.com/Knetic/govaluate"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpressionCache_Get(t *testing.T) {
	tests := []struct {
		name          string
		expression    string
		withFunctions bool
		expectError   bool
		expectCached  bool
	}{
		{
			name:        "simple expression",
			expression:  "2 + 2",
			expectError: false,
		},
		{
			name:        "variable expression",
			expression:  "x + y",
			expectError: false,
		},
		{
			name:         "invalid expression",
			expression:   "2 + + 2",
			expectError:  true,
			expectCached: false,
		},
		{
			name:          "function expression",
			expression:    "len('test')",
			withFunctions: true,
			expectError:   false,
		},
		{
			name:        "complex expression",
			expression:  "(x > 5) && (y < 10)",
			expectError: false,
		},
		{
			name:        "empty expression",
			expression:  "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cache *ExpressionCache
			if tt.withFunctions {
				testFunctions := map[string]govaluate.ExpressionFunction{
					"len": func(args ...interface{}) (interface{}, error) {
						if len(args) != 1 {
							return nil, assert.AnError
						}
						if str, ok := args[0].(string); ok {
							return len(str), nil
						}
						return 0, nil
					},
				}
				cache = NewWithFunctions(testFunctions)
			} else {
				cache = New()
			}

			compiled, err := cache.Get(tt.expression)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, compiled)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, compiled)

			compiled2, err2 := cache.Get(tt.expression)
			require.NoError(t, err2)
			assert.Same(t, compiled, compiled2, "Expression should be cached")

			assert.Equal(t, 1, cache.Size())
		})
	}
}

func TestExpressionCache_Clear(t *testing.T) {
	cache := New()

	_, err := cache.Get("2 + 2")
	require.NoError(t, err)
	assert.Equal(t, 1, cache.Size())

	cache.Clear()
	assert.Equal(t, 0, cache.Size())

	_, err = cache.Get("2 + 2")
	require.NoError(t, err)
	assert.Equal(t, 1, cache.Size())
}

func TestExpressionCache_ConcurrentAccess(t *testing.T) {
	cache := New()
	expression := "x + y + z"

	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()
			for j := 0; j < 100; j++ {
				compiled, err := cache.Get(expression)
				assert.NoError(t, err)
				assert.NotNil(t, compiled)
			}
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	assert.Equal(t, 1, cache.Size())
}

func TestGlobalCaches(t *testing.T) {
	t.Run("DefaultCache", func(t *testing.T) {
		expr, err := GetCompiledExpression("2 + 2")
		require.NoError(t, err)
		assert.NotNil(t, expr)

		result, err := expr.Evaluate(nil)
		require.NoError(t, err)
		assert.Equal(t, float64(4), result)
	})

	t.Run("DSLCache", func(t *testing.T) {
		expr, err := GetCompiledDSLExpression("2 + 2")
		require.NoError(t, err)
		assert.NotNil(t, expr)

		result, err := expr.Evaluate(nil)
		require.NoError(t, err)
		assert.Equal(t, float64(4), result)
	})
}

func TestExpressionCache_Size(t *testing.T) {
	cache := New()
	assert.Equal(t, 0, cache.Size())

	expressions := []string{"1+1", "2+2", "3+3"}
	for i, expr := range expressions {
		_, err := cache.Get(expr)
		require.NoError(t, err)
		assert.Equal(t, i+1, cache.Size())
	}
}

func BenchmarkExpressionCache_Get(b *testing.B) {
	cache := New()
	expression := "x + y + z + a + b"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cache.Get(expression)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkExpressionCache_GetParallel(b *testing.B) {
	cache := New()
	expression := "x + y + z + a + b"

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := cache.Get(expression)
			if err != nil {
				b.Fatal(err)
			}
		}
	})
}
