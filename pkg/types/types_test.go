package types

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOptionsCopyPreservesUserAgentTag verifies that Copy() carries the ua-tag
// value over, so requests built from cloned options keep the User-Agent tag.
func TestOptionsCopyPreservesUserAgentTag(t *testing.T) {
	opts := &Options{UserAgentTag: "scanner-xyz/1.0"}
	require.Equal(t, "scanner-xyz/1.0", opts.Copy().UserAgentTag, "Copy() should preserve UserAgentTag")
}
