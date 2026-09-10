package proxy

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadOrCreateCAGeneratesUsableAuthority(t *testing.T) {
	dir := t.TempDir()

	ca, err := LoadOrCreateCA(dir)
	require.NoError(t, err)
	require.NotNil(t, ca.Certificate.Leaf)
	require.True(t, ca.Certificate.Leaf.IsCA)
	require.True(t, ca.Certificate.Leaf.MaxPathLenZero, "CA must not be able to issue sub authorities")
	require.Contains(t, string(ca.CertPEM), "BEGIN CERTIFICATE")
	require.NotContains(t, string(ca.CertPEM), "PRIVATE KEY")
	require.Equal(t, filepath.Join(dir, caCertFileName), ca.CertPath)
}

func TestLoadOrCreateCAKeyIsOwnerReadableOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes only")
	}
	dir := t.TempDir()

	_, err := LoadOrCreateCA(dir)
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(dir, caKeyFileName))
	require.NoError(t, err)
	require.Equal(t, caKeyFileMode, info.Mode().Perm())
}

func TestLoadOrCreateCAReusesExistingAuthority(t *testing.T) {
	dir := t.TempDir()

	first, err := LoadOrCreateCA(dir)
	require.NoError(t, err)
	second, err := LoadOrCreateCA(dir)
	require.NoError(t, err)

	require.Equal(t, first.Certificate.Leaf.SerialNumber, second.Certificate.Leaf.SerialNumber)
}

func TestLoadOrCreateCARejectsGroupReadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix file modes only")
	}
	dir := t.TempDir()

	_, err := LoadOrCreateCA(dir)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(filepath.Join(dir, caKeyFileName), 0o644))

	_, err = LoadOrCreateCA(dir)
	require.ErrorContains(t, err, "readable by other users")
}
