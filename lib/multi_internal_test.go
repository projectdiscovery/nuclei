package nuclei

import (
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
