package expressions

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

func TestCompileExpressionReusesParse(t *testing.T) {
	const source = `to_upper('parse-cache-reuse')`

	first, err := compileExpression(source)
	require.NoError(t, err)

	second, err := compileExpression(source)
	require.NoError(t, err)
	require.Same(t, first, second, "a repeated source should reuse the parsed expression")

	result, err := second.Evaluate(nil)
	require.NoError(t, err)
	require.Equal(t, "PARSE-CACHE-REUSE", result)
}

func TestCompileExpressionDoesNotCacheFailures(t *testing.T) {
	const name = "parse_cache_late_helper"
	source := name + `('x')`

	_, err := compileExpression(source)
	require.Error(t, err, "an unregistered helper should not compile")

	dsl.HelperFunctions[name] = func(args ...interface{}) (interface{}, error) { return "ok", nil }
	t.Cleanup(func() { delete(dsl.HelperFunctions, name) })

	compiled, err := compileExpression(source)
	require.NoError(t, err, "a helper registered after a failed parse must compile")

	result, err := compiled.Evaluate(nil)
	require.NoError(t, err)
	require.Equal(t, "ok", result)
}

func TestParsesWithoutFunctions(t *testing.T) {
	require.True(t, parsesWithoutFunctions(`1 + 2`))
	require.True(t, parsesWithoutFunctions(`1 + 2`), "cached answer must match")
	require.False(t, parsesWithoutFunctions(`to_upper('a')`))
	require.False(t, parsesWithoutFunctions(`to_upper('a')`), "cached answer must match")
}

func TestEvaluateConcurrentWithSharedParse(t *testing.T) {
	var wg sync.WaitGroup
	for worker := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 200 {
				name := fmt.Sprintf("w%d-%d", worker, i)
				got, err := Evaluate(`{{concat(to_lower(name), '-', hex_encode('abc'))}}`, map[string]interface{}{"name": name})
				if err != nil || got != name+"-616263" {
					t.Errorf("unexpected result %q: %v", got, err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestEvaluateDoesNotCacheInlinedValues(t *testing.T) {
	body := strings.Repeat("A", 64*1024)
	for i := range 20 {
		value := fmt.Sprintf("%s-%d", body, i)
		_, err := Evaluate(`{{md5('{{body}}')}}`, map[string]interface{}{"body": value})
		require.NoError(t, err)
	}

	compiledCache.entries.Range(func(key, _ any) bool {
		require.LessOrEqual(t, len(key.(string)), maxCachedSourceLen, "a source with an inlined value must not be cached")
		return true
	})
}

func TestBoundedCacheClearsWhenFull(t *testing.T) {
	var cache boundedCache[int]
	for i := range parseCacheEntries + 10 {
		cache.store(fmt.Sprint(i), i)
	}

	entries := 0
	cache.entries.Range(func(_, _ any) bool { entries++; return true })
	require.LessOrEqual(t, entries, parseCacheEntries)

	value, ok := cache.load(fmt.Sprint(parseCacheEntries + 9))
	require.True(t, ok, "the latest entry must survive a clear")
	require.Equal(t, parseCacheEntries+9, value)
}

func BenchmarkEvaluateRepeatedRequestTemplateParallel(b *testing.B) {
	values := map[string]interface{}{"BaseURL": "https://example.com", "Hostname": "example.com"}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := Evaluate(`{{BaseURL}}/path?id={{base64(to_lower(Hostname))}}&x={{md5('static')}}`, values); err != nil {
				b.Error(err)
				return
			}
		}
	})
}

func BenchmarkEvaluateRepeatedRequestTemplate(b *testing.B) {
	values := map[string]interface{}{"BaseURL": "https://example.com", "Hostname": "example.com"}
	b.ReportAllocs()
	for b.Loop() {
		got, err := Evaluate(`{{BaseURL}}/path?id={{base64(to_lower(Hostname))}}&x={{md5('static')}}`, values)
		if err != nil || got == "" {
			b.Fatalf("unexpected result %q: %v", got, err)
		}
	}
}
