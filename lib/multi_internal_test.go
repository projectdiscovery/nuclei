package nuclei

import (
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/assert"
)

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
