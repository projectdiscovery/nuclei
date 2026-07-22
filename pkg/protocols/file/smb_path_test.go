package file

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsSMBPath(t *testing.T) {
	require.True(t, IsSMBPath(`\\fs01\backup\a.txt`))
	require.True(t, IsSMBPath(`//fs01/backup/a.txt`))
	require.True(t, IsSMBPath(`smb://fs01/backup/a.txt`))
	require.True(t, IsSMBPath(`SMB://user:pass@fs01/share/`))
	require.False(t, IsSMBPath(`/tmp/a.txt`))
	require.False(t, IsSMBPath(`C:\Windows\a.txt`))
	require.False(t, IsSMBPath(``))
}

func TestParseSMBTargetUNC(t *testing.T) {
	got, err := ParseSMBTarget(`\\fs01\backup\docs\creds.txt`)
	require.NoError(t, err)
	require.Equal(t, "fs01", got.Host)
	require.Equal(t, "backup", got.Share)
	require.Equal(t, "docs/creds.txt", got.Path)
	require.Equal(t, 445, got.Port)
	require.Equal(t, `\\fs01\backup\docs\creds.txt`, got.Display())
}

func TestParseSMBTargetUNCShareRoot(t *testing.T) {
	got, err := ParseSMBTarget(`\\fs01\backup`)
	require.NoError(t, err)
	require.Equal(t, "backup", got.Share)
	require.Equal(t, ".", got.Path)
	require.Equal(t, `\\fs01\backup`, got.Display())
}

func TestParseSMBTargetURL(t *testing.T) {
	got, err := ParseSMBTarget(`smb://auditor:secret@fs01:1445/backup/a.txt`)
	require.NoError(t, err)
	require.Equal(t, "fs01", got.Host)
	require.Equal(t, 1445, got.Port)
	require.Equal(t, "backup", got.Share)
	require.Equal(t, "a.txt", got.Path)
	require.Equal(t, "auditor", got.User)
	require.Equal(t, "secret", got.Password)
}

func TestParseSMBTargetURLWithDomain(t *testing.T) {
	got, err := ParseSMBTarget(`smb://CORP;alice:p@fs01/share/x`)
	require.NoError(t, err)
	require.Equal(t, "CORP", got.Domain)
	require.Equal(t, "alice", got.User)
	require.Equal(t, "p", got.Password)
	require.Equal(t, "share", got.Share)
	require.Equal(t, "x", got.Path)
}

func TestParseSMBTargetRejectsEscape(t *testing.T) {
	_, err := ParseSMBTarget(`\\fs01\backup\..\..\Windows\win.ini`)
	require.Error(t, err)
}

func TestParseSMBTargetRejectsBadShare(t *testing.T) {
	_, err := ParseSMBTarget(`smb://fs01/bad/share/x`)
	// share is "bad", path is "share/x" — valid
	require.NoError(t, err)
	_, err = ParseSMBTarget(`\\fs01\`)
	require.Error(t, err)
}

func TestResolveSMBCredsPreferURL(t *testing.T) {
	req := &Request{SMBUser: "tmpl", SMBPassword: "tmpl-pass", SMBDomain: "TMPL"}
	target := &SMBTarget{User: "urluser", Password: "urlpass", Domain: "URLDOM"}
	creds := req.resolveSMBCreds(target)
	require.Equal(t, "urluser", creds.User)
	require.Equal(t, "urlpass", creds.Password)
	require.Equal(t, "URLDOM", creds.Domain)
}

func TestResolveSMBCredsParseIdentity(t *testing.T) {
	req := &Request{SMBUser: `CORP\bob`, SMBPassword: "x"}
	creds := req.resolveSMBCreds(&SMBTarget{})
	require.Equal(t, "CORP", creds.Domain)
	require.Equal(t, "bob", creds.User)
}

func TestIsDirectorySMBTarget(t *testing.T) {
	require.True(t, isDirectorySMBTarget(`\\fs01\backup`))
	require.True(t, isDirectorySMBTarget(`smb://fs01/backup/`))
	require.False(t, isDirectorySMBTarget(`\\fs01\backup\a.txt`))
}
