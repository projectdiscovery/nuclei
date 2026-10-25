package templates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"github.com/stretchr/testify/require"
)

func TestTemplateSignerSupportsProgrammaticImportedFiles(t *testing.T) {
	templateSigner, err := signer.NewTemplateSignerFromFiles("signer/testdata/ci.crt", "signer/testdata/ci-private-key.pem")
	require.NoError(t, err)

	importPath := filepath.Join(t.TempDir(), "import.js")
	require.NoError(t, os.WriteFile(importPath, []byte("programmatic import"), 0o600))
	template := &Template{ImportedFiles: []string{importPath}}
	templateData := []byte("id: programmatic-import")

	signature, err := templateSigner.Sign(templateData, template)
	require.NoError(t, err)
	signedData := append(templateData, []byte("\n"+signature)...)
	verified, err := templateSigner.Verify(signedData, template)
	require.NoError(t, err)
	require.True(t, verified)
}
