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
