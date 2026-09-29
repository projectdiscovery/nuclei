package smbsession

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseIdentity(t *testing.T) {
	d, u := ParseIdentity(`CORP\alice`)
	require.Equal(t, "CORP", d)
	require.Equal(t, "alice", u)

	d, u = ParseIdentity("alice@corp.local")
	require.Equal(t, "corp.local", d)
	require.Equal(t, "alice", u)

	d, u = ParseIdentity("alice")
	require.Equal(t, "", d)
	require.Equal(t, "alice", u)
}

func TestNormalizeSharePath(t *testing.T) {
	got, err := NormalizeSharePath(`docs\a.txt`)
	require.NoError(t, err)
	require.Equal(t, "docs/a.txt", got)

	_, err = NormalizeSharePath("../etc")
	require.Error(t, err)

	got, err = NormalizeSharePath("")
	require.NoError(t, err)
	require.Equal(t, ".", got)
}

func TestRequireShareName(t *testing.T) {
	require.Error(t, RequireShareName(""))
	require.Error(t, RequireShareName("a/b"))
	require.NoError(t, RequireShareName("C$"))
}
