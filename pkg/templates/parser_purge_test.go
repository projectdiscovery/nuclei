package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestParserPurgeClearsCaches ensures Purge drops both the parsed and compiled
// template caches so a long-running embedder does not retain compiled templates
// (heap-heavy objects) for the entire process lifetime.
func TestParserPurgeClearsCaches(t *testing.T) {
	p := NewParser()

	p.Cache().Store("tpl-a", &Template{}, []byte("raw"), nil)
	p.CompiledCache().Store("tpl-a", &Template{}, []byte("raw"), nil)
	require.Equal(t, 1, p.ParsedCount(), "parsed cache should hold the stored template")
	require.Equal(t, 1, p.CompiledCount(), "compiled cache should hold the stored template")

	p.Purge()

	require.Equal(t, 0, p.ParsedCount(), "parsed cache must be empty after Purge")
	require.Equal(t, 0, p.CompiledCount(), "compiled cache must be empty after Purge")
}
func TestParserExecutionParserSharesOnlyParsedCache(t *testing.T) {
	parent := NewParser()
	parent.ShouldValidate = true
	parent.NoStrictSyntax = true
	parent.Cache().Store("parsed", &Template{}, []byte("raw"), nil)
	parent.CompiledCache().StoreWithoutRaw("parent-compiled", &Template{}, nil)

	execution := NewExecutionParser(parent)
	sibling := NewExecutionParser(parent)

	require.Same(t, parent.Cache(), execution.Cache())
	require.Same(t, parent.Cache(), sibling.Cache())
	require.NotSame(t, parent.CompiledCache(), execution.CompiledCache())
	require.NotSame(t, execution.CompiledCache(), sibling.CompiledCache())
	require.True(t, execution.ShouldValidate)
	require.True(t, execution.NoStrictSyntax)
	require.Equal(t, 1, execution.ParsedCount())
	require.Zero(t, execution.CompiledCount())

	execution.CompiledCache().StoreWithoutRaw("execution-compiled", &Template{}, nil)
	require.Equal(t, 1, execution.CompiledCount())
	require.Zero(t, sibling.CompiledCount())
	require.Equal(t, 1, parent.CompiledCount())
}

func TestParserPurgeCompiledPreservesSharedParsedCache(t *testing.T) {
	parent := NewParser()
	parent.Cache().Store("parsed", &Template{}, []byte("raw"), nil)
	execution := NewExecutionParser(parent)
	execution.CompiledCache().StoreWithoutRaw("compiled", &Template{}, nil)

	execution.PurgeCompiled()

	require.Zero(t, execution.CompiledCount())
	require.Equal(t, 1, execution.ParsedCount())
	require.Equal(t, 1, parent.ParsedCount())
}
