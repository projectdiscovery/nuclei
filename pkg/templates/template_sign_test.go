package templates

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
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

func TestTemplateVerificationReusesVerdictOnlyForSameContentAndVerifier(t *testing.T) {
	templateSigner, err := signer.NewTemplateSignerFromFiles("signer/testdata/ci.crt", "signer/testdata/ci-private-key.pem")
	require.NoError(t, err)
	defaultVerifiers := signer.DefaultTemplateVerifiers
	signer.DefaultTemplateVerifiers = append([]*signer.TemplateSigner{templateSigner}, defaultVerifiers...)
	t.Cleanup(func() {
		signer.DefaultTemplateVerifiers = defaultVerifiers
	})

	content := []byte("id: verification-cache")
	signature, err := templateSigner.Sign(content, &Template{})
	require.NoError(t, err)
	signed := append(content, []byte("\n"+signature)...)
	verify := func(data []byte) bool {
		template := &Template{Options: &protocols.ExecutorOptions{}, importedFileContentsCaptured: true}
		applyTemplateVerification(template, data)
		return template.Verified
	}

	require.True(t, verify(signed))

	// A reused verdict skips the signature check, which allocates.
	template := &Template{importedFileContentsCaptured: true}
	digest, err := templateVerificationDigest(signed, template)
	require.NoError(t, err)
	var verifier *signer.TemplateSigner
	require.Zero(t, testing.AllocsPerRun(10, func() {
		verifier = templateVerifier(template, signed, digest, true)
	}))
	require.Same(t, templateSigner, verifier)

	tampered := bytes.Replace(signed, []byte("verification-cache"), []byte("tampered-template"), 1)
	require.False(t, verify(tampered))

	signer.DefaultTemplateVerifiers = defaultVerifiers
	require.False(t, verify(signed))
}
