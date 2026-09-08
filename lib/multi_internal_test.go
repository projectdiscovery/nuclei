package nuclei

import (
	"context"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEphemeralObjectsUseExecutionLocalParser(t *testing.T) {
	baseParser := templates.NewParser()
	baseParser.Cache().Store("parsed", &templates.Template{}, []byte("raw"), nil)
	base := &NucleiEngine{parser: baseParser}

	first, err := createEphemeralObjects(context.Background(), base, types.DefaultOptions(), nil)
	require.NoError(t, err)
	second, err := createEphemeralObjects(context.Background(), base, types.DefaultOptions(), nil)
	require.NoError(t, err)
	t.Cleanup(func() { closeEphemeralObjects(second) })

	firstParser, ok := first.executerOpts.Parser.(*templates.Parser)
	require.True(t, ok)
	secondParser, ok := second.executerOpts.Parser.(*templates.Parser)
	require.True(t, ok)

	require.NotSame(t, baseParser, firstParser)
	require.NotSame(t, firstParser, secondParser)
	require.Same(t, baseParser.Cache(), firstParser.Cache())
	require.Same(t, baseParser.Cache(), secondParser.Cache())
	require.NotSame(t, firstParser.CompiledCache(), secondParser.CompiledCache())
	require.False(t, first.executerOpts.DoNotCache)

	firstParser.CompiledCache().StoreWithoutRaw("compiled", &templates.Template{}, nil)
	require.Equal(t, 1, firstParser.CompiledCount())
	require.Zero(t, secondParser.CompiledCount())

	closeEphemeralObjects(first)
	require.Zero(t, firstParser.CompiledCount())
	require.Equal(t, 1, baseParser.ParsedCount())
}

func TestRestoreBaseExcludeTags(t *testing.T) {
	tests := []struct {
		name     string
		base     []string
		current  []string
		expected []string
	}{
		{
			name:     "per-execution filter cleared the deny-list",
			base:     []string{"dos", "fuzz"},
			current:  nil,
			expected: []string{"dos", "fuzz"},
		},
		{
			name:     "per-execution exclusions are kept alongside the baseline",
			base:     []string{"dos"},
			current:  []string{"custom"},
			expected: []string{"custom", "dos"},
		},
		{
			name:     "entries already present are not duplicated",
			base:     []string{"dos", "fuzz"},
			current:  []string{"fuzz"},
			expected: []string{"fuzz", "dos"},
		},
		{
			name:     "no baseline is a no-op",
			base:     nil,
			current:  []string{"custom"},
			expected: []string{"custom"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := &types.Options{ExcludeTags: tt.current}
			restoreBaseExcludeTags(tt.base, opts)
			assert.Equal(t, tt.expected, []string(opts.ExcludeTags))
		})
	}
}

// TestRestoreBaseExcludeTagsIsIdempotent matters because the helper runs on
// every execution against a long-lived engine.
func TestRestoreBaseExcludeTagsIsIdempotent(t *testing.T) {
	opts := &types.Options{}
	restoreBaseExcludeTags([]string{"dos", "fuzz"}, opts)
	restoreBaseExcludeTags([]string{"dos", "fuzz"}, opts)

	assert.Equal(t, []string{"dos", "fuzz"}, []string(opts.ExcludeTags))
}

// TestRestoreBaseExcludeTagsDoesNotMutateCallerSlice guards the concurrent
// ThreadSafeNucleiEngine case where WithTemplateFilters assigns a caller-owned
// ExcludeTags slice with spare capacity: a naive append would race and mutate
// the caller's backing array.
func TestRestoreBaseExcludeTagsDoesNotMutateCallerSlice(t *testing.T) {
	shared := make([]string, 1, 8)
	shared[0] = "custom"
	base := []string{"dos", "fuzz"}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			opts := &types.Options{ExcludeTags: shared}
			restoreBaseExcludeTags(base, opts)
			if got := []string(opts.ExcludeTags); len(got) != 3 || got[0] != "custom" || got[1] != "dos" || got[2] != "fuzz" {
				panic(got)
			}
		}()
	}
	wg.Wait()

	assert.Equal(t, []string{"custom"}, shared[:1])
	assert.Equal(t, make([]string, 7), shared[1:cap(shared)])
}
