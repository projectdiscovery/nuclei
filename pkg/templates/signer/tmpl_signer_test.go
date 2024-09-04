package signer

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testCertFile = "../../../integration_tests/protocols/keys/ci.crt"
	testKeyFile  = "../../../integration_tests/protocols/keys/ci-private-key.pem"
)

type mockSignableTemplate struct {
	imports []string
	hasCode bool
}

func (m *mockSignableTemplate) GetFileImports() []string {
	return m.imports
}

func (m *mockSignableTemplate) HasCodeProtocol() bool {
	return m.hasCode
}

var signer, _ = NewTemplateSignerFromFiles(testCertFile, testKeyFile)

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
