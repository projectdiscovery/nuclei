package signer

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCertFile = "testdata/ci.crt"
	testKeyFile  = "testdata/ci-private-key.pem"
)

type mockSignableTemplate struct {
	imports       []string
	hasCode       bool
	hasJavascript bool
}

type snapshotSignableTemplate struct {
	imports        []string
	importContents [][]byte
	captured       bool
}

func (m *mockSignableTemplate) GetFileImports() []string {
	return m.imports
}

func (m *mockSignableTemplate) HasCodeProtocol() bool {
	return m.hasCode
}

func (m *mockSignableTemplate) HasJavascriptRequest(...int) bool {
	return m.hasJavascript
}

func (m *snapshotSignableTemplate) GetFileImports() []string {
	return m.imports
}

func (m *snapshotSignableTemplate) GetFileImportContents() ([][]byte, bool) {
	return m.importContents, m.captured
}

func (m *snapshotSignableTemplate) HasCodeProtocol() bool {
	return false
}

var signer, _ = NewTemplateSignerFromFiles(testCertFile, testKeyFile)

func TestPublicKeyFragmentTrimsLeadingZeroXCoordinate(t *testing.T) {
	publicKey, publicKeyBytes := p256PublicKeyWithLeadingZeroX(t)
	xCoordinate := publicKeyBytes[1:33]
	require.Zero(t, xCoordinate[0])

	legacyXCoordinate := bytes.TrimLeft(xCoordinate, "\x00")
	legacyHash := md5.Sum(legacyXCoordinate)
	untrimmedHash := md5.Sum(xCoordinate)
	require.NotEqual(t, untrimmedHash, legacyHash)

	fragment, err := publicKeyFragment(publicKey)
	require.NoError(t, err)
	require.Equal(t, fmt.Sprintf("%x", legacyHash), fragment)
}

func p256PublicKeyWithLeadingZeroX(t *testing.T) (*ecdsa.PublicKey, []byte) {
	t.Helper()

	var privateKeyBytes [32]byte
	for i := uint64(1); i < 10_000; i++ {
		binary.BigEndian.PutUint64(privateKeyBytes[24:], i)
		privateKey, err := ecdh.P256().NewPrivateKey(privateKeyBytes[:])
		require.NoError(t, err)

		publicKeyBytes := privateKey.PublicKey().Bytes()
		require.Len(t, publicKeyBytes, 65)
		require.Equal(t, byte(4), publicKeyBytes[0])
		if publicKeyBytes[1] != 0 {
			continue
		}

		publicKey, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKeyBytes)
		require.NoError(t, err)
		return publicKey, publicKeyBytes
	}
	t.Fatal("failed to find a P-256 public key with a leading-zero x-coordinate")
	return nil, nil
}

func TestTemplateSignerSignAndVerify(t *testing.T) {
	tempDir := t.TempDir()

	tests := []struct {
		name            string
		data            []byte
		tmpl            SignableTemplate
		wantSignErr     bool
		wantVerifyErr   bool
		wantVerified    bool
		modifyAfterSign func([]byte) []byte
	}{
		{
			name:         "Simple template",
			data:         []byte("id: test-template\ninfo:\n  name: Test Template"),
			tmpl:         &mockSignableTemplate{},
			wantVerified: true,
		},
		{
			name:         "Template with CRLF line endings",
			data:         []byte("id: test-template\r\ninfo:\r\n  name: Test Template"),
			tmpl:         &mockSignableTemplate{},
			wantVerified: true,
		},
		{
			name: "Template with imports",
			data: []byte("id: test-template\ninfo:\n  name: Test Template"),
			tmpl: &mockSignableTemplate{imports: []string{
				filepath.Join(tempDir, "import1.yaml"),
				filepath.Join(tempDir, "import2.yaml"),
			}},
			wantVerified: true,
		},
		{
			name:         "Template with code protocol",
			data:         []byte("id: test-template\ninfo:\n  name: Test Template\n\ncode:\n  - engine: bash\n    source: echo 'Hello, World!'"),
			tmpl:         &mockSignableTemplate{hasCode: true},
			wantSignErr:  false,
			wantVerified: true,
		},
		{
			name: "Tampered template",
			data: []byte("id: test-template\ninfo:\n  name: Test Template"),
			tmpl: &mockSignableTemplate{},
			modifyAfterSign: func(data []byte) []byte {
				signatureIndex := bytes.LastIndex(data, []byte(SignaturePattern))
				if signatureIndex == -1 {
					return data
				}
				return append(data[:signatureIndex], append([]byte("# Tampered content\n"), data[signatureIndex:]...)...)
			},
			wantVerified: false,
		},
		{
			name: "Invalid signature",
			data: []byte("id: test-template\ninfo:\n  name: Test Template"),
			tmpl: &mockSignableTemplate{},
			modifyAfterSign: func(data []byte) []byte {
				return append(bytes.TrimSuffix(data, []byte("\n")), []byte("\n# digest: invalid_signature:fragment")...)
			},
			wantVerifyErr: true,
			wantVerified:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create import files if needed
			for _, imp := range tt.tmpl.GetFileImports() {
				err := os.WriteFile(imp, []byte("imported content"), 0644)
				require.NoError(t, err, "Failed to create import file")
			}

			// Sign the template
			signature, err := signer.Sign(tt.data, tt.tmpl)
			if tt.wantSignErr {
				assert.Error(t, err, "Expected an error during signing")
				return
			}
			require.NoError(t, err, "Failed to sign template")

			// Append signature to the template data
			signedData := append(tt.data, []byte("\n"+signature)...)

			// Apply any modifications after signing if specified
			if tt.modifyAfterSign != nil {
				signedData = tt.modifyAfterSign(signedData)
			}

			// Verify the signature
			verified, err := signer.Verify(signedData, tt.tmpl)
			if tt.wantVerifyErr {
				assert.Error(t, err, "Expected an error during verification")
			} else {
				assert.NoError(t, err, "Unexpected error during verification")
			}
			assert.Equal(t, tt.wantVerified, verified, "Unexpected verification result")
		})
	}
}

func TestTemplateSignerUsesImportedContentSnapshot(t *testing.T) {
	importPath := filepath.Join(t.TempDir(), "import.js")
	require.NoError(t, os.WriteFile(importPath, []byte("disk content before signing"), 0o600))

	tmpl := &snapshotSignableTemplate{
		imports:        []string{importPath},
		importContents: [][]byte{[]byte("loaded content")},
		captured:       true,
	}
	templateData := []byte("id: imported-content-snapshot")
	signature, err := signer.Sign(templateData, tmpl)
	require.NoError(t, err)

	require.NoError(t, os.WriteFile(importPath, []byte("disk content after signing"), 0o600))
	signedData := append(templateData, []byte("\n"+signature)...)
	verified, err := signer.Verify(signedData, tmpl)
	require.NoError(t, err)
	require.True(t, verified)
}

func TestTemplateSignerRejectsMismatchedImportedContentSnapshot(t *testing.T) {
	importPath := filepath.Join(t.TempDir(), "import.js")
	require.NoError(t, os.WriteFile(importPath, []byte("disk content"), 0o600))

	tmpl := &snapshotSignableTemplate{imports: []string{importPath}, captured: true}
	_, err := signer.Sign([]byte("id: incomplete-import-snapshot"), tmpl)
	require.ErrorContains(t, err, "imported-file content count does not match imported-file path count")
}

func TestTemplateSignerRejectsResigningJavascriptWithForeignSigner(t *testing.T) {
	tmpl := &mockSignableTemplate{hasJavascript: true}
	templateData := []byte("id: javascript-template\n# digest: 00:foreign-signer")

	_, err := signer.Sign(templateData, tmpl)
	require.ErrorContains(t, err, "re-signing executable templates are not allowed")
}
