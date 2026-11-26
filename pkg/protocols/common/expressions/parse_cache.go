package expressions

import (
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/govaluate"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/common/dsl"
)

const (
	// parseCacheEntries bounds how many sources each cache holds. Template
	// expressions repeat on every request and target, so the working set is
	// small; a full cache is cleared and refills with what is still in use.
	parseCacheEntries = 4096

	// maxCachedSourceLen keeps sources carrying large inlined values, such as
	// a response body, out of the cache. Those change on every call, so caching
	// them would only pin memory.
	maxCachedSourceLen = 1024
)

// boundedCache is a concurrent map with lock-free reads. Expressions are
// looked up from every scan goroutine, so reads must not contend on a lock.
type boundedCache[V any] struct {
	entries sync.Map
	size    atomic.Int64
}

func (c *boundedCache[V]) load(key string) (V, bool) {
	value, ok := c.entries.Load(key)
	if !ok {
		var zero V
		return zero, false
	}
	return value.(V), true
}

func (c *boundedCache[V]) store(key string, value V) {
	if c.size.Add(1) > parseCacheEntries {
		c.entries.Clear()
		c.size.Store(1)
	}
	c.entries.Store(key, value)
}

var (
	// compiledCache holds expressions parsed with the DSL helper functions.
	// Only successful parses are stored: helpers can be registered at runtime,
	// so a failure now may succeed later.
	compiledCache boundedCache[*govaluate.EvaluableExpression]

	// plainParseCache holds whether a source parses without any helper
	// functions. That outcome does not depend on runtime state.
	plainParseCache boundedCache[bool]
)

// compileExpression parses source with the DSL helper functions, reusing a
// previous parse of the same source. A parsed expression is immutable and safe
// to evaluate from several goroutines.
func compileExpression(source string) (*govaluate.EvaluableExpression, error) {
	cacheable := len(source) <= maxCachedSourceLen
	if cacheable {
		if cached, ok := compiledCache.load(source); ok {
			return cached, nil
		}
	}

	compiled, err := govaluate.NewEvaluableExpressionWithFunctions(source, dsl.HelperFunctions)
	if err != nil {
		return nil, err
	}

	if cacheable {
		compiledCache.store(source, compiled)
	}

	return compiled, nil
}

// parsesWithoutFunctions reports whether source is a valid expression that
// needs no helper functions.
func parsesWithoutFunctions(source string) bool {
	cacheable := len(source) <= maxCachedSourceLen
	if cacheable {
		if ok, found := plainParseCache.load(source); found {
			return ok
		}
	}

	_, err := govaluate.NewEvaluableExpression(source)
	ok := err == nil

	if cacheable {
		plainParseCache.store(source, ok)
	}

	return ok
}
