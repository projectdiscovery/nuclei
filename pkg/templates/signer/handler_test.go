package signer

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/stretchr/testify/require"
)

// This Unit Test generates a new key pair and parses it
// to ensure that the key handler works as expected.
func TestKeyHandler(t *testing.T) {
	if val := os.Getenv("KEY_HANDLER_CI"); val != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestKeyHandler$", "-test.v")
		cmd.Env = append(cmd.Env, "KEY_HANDLER_CI=1")
		var buff bytes.Buffer
		cmd.Stdin = &buff
		buff.WriteString("CIUSER\n")
		buff.WriteString("\n")
		out, err := cmd.CombinedOutput()
		if !strings.Contains(string(out), "PASS\n") || err != nil {
			t.Fatalf("%s\n(exit status %v)", string(out), err)
		}
		return
	}
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	h := &KeyHandler{}
	noUserPassphrase = true
	h.GenerateKeyPair()
	if h.UserCert == nil {
		t.Fatal("no user cert found")
	}
	if h.PrivateKey == nil {
		t.Fatal("no private key found")
	}

	// now parse the cert and private key
	if err := h.ParseUserCert(); err != nil {
		t.Fatal(err)
	}
	if err := h.ParsePrivateKey(); err != nil {
		t.Fatal(err)
	}
	if h.ecdsaKey == nil {
		t.Fatal("no ecdsa key found")
	}
	if h.ecdsaPubKey == nil {
		t.Fatal("no ecdsa public key found")
	}
	if h.cert == nil {
		t.Fatal("no certificate found")
	}
	if h.cert.Subject.CommonName != "CIUSER" {
		t.Fatal("invalid user name found")
	}
}

func TestReadCertAndPrivateKeyOversize(t *testing.T) {
	origLimit := MaxFileSize
	MaxFileSize = 64
	defer func() {
		MaxFileSize = origLimit
	}()

	tmpDir := t.TempDir()
	oversizedData := bytes.Repeat([]byte("A"), 128)

	certFile := filepath.Join(tmpDir, CertFilename)
	err := os.WriteFile(certFile, oversizedData, 0644)
	require.NoError(t, err)

	keyFile := filepath.Join(tmpDir, PrivateKeyFilename)
	err = os.WriteFile(keyFile, oversizedData, 0644)
	require.NoError(t, err)

	h := &KeyHandler{}
	err = h.ReadCert("", tmpDir)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFileTooLarge))

	err = h.ReadPrivateKey("", tmpDir)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFileTooLarge))
}

func TestNewTemplateSignerFromFilesOversize(t *testing.T) {
	origLimit := MaxFileSize
	MaxFileSize = 64
	defer func() {
		MaxFileSize = origLimit
	}()

	tmpDir := t.TempDir()
	oversizedFile := filepath.Join(tmpDir, "oversized.pem")
	err := os.WriteFile(oversizedFile, bytes.Repeat([]byte("A"), 128), 0644)
	require.NoError(t, err)

	normalFile := filepath.Join(tmpDir, "normal.pem")
	err = os.WriteFile(normalFile, []byte("normal content"), 0644)
	require.NoError(t, err)

	_, err = NewTemplateSignerFromFiles(oversizedFile, normalFile)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFileTooLarge))

	_, err = NewTemplateSignerFromFiles(normalFile, oversizedFile)
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrFileTooLarge))
}
