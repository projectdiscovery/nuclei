package smb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSmbMemoKeyUnambiguousAndHashed(t *testing.T) {
	a := smbMemoKey("listDir", "exec", "host", "445", "user:a", "pass", "share", "dir")
	b := smbMemoKey("listDir", "exec", "host", "445", "user", "a:pass", "share", "dir")
	require.NotEqual(t, a, b, "colon in credentials must not collide keys")
	require.Contains(t, a, "listDir:")
	require.NotContains(t, a, "pass")
	require.NotContains(t, a, "user:a")
}
