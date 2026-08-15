package templates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/stretchr/testify/require"
)

func TestCloneTemplatePreservesCleanTemplateIsolation(t *testing.T) {
	templatePath := filepath.Join(t.TempDir(), "multi-protocol.yaml")
	require.NoError(t, os.WriteFile(templatePath, []byte(`id: clone-isolation

info:
  name: Clone isolation
  author: pdteam
  severity: info

variables:
  shared: original

dns:
  - name: "{{FQDN}}"
    type: A

http:
  - method: GET
    path:
      - "{{BaseURL}}"
    matchers:
      - type: word
        words:
          - original
`), 0o600))

	parsed, err := NewParser().ParseTemplate(templatePath, disk.NewCatalog(""))
	require.NoError(t, err)
	original := parsed.(*Template)
	cloned := cloneTemplate(original)

	require.NotSame(t, original, cloned)
	require.NotSame(t, original.RequestsDNS[0], cloned.RequestsDNS[0])
	require.NotSame(t, original.RequestsHTTP[0], cloned.RequestsHTTP[0])
	require.Same(t, cloned.RequestsDNS[0], cloned.RequestsQueue[0])
	require.Same(t, cloned.RequestsHTTP[0], cloned.RequestsQueue[1])

	cloned.RequestsHTTP[0].Matchers[0].Words[0] = "changed"
	cloned.Variables.Set("shared", "changed")
	require.Equal(t, "original", original.RequestsHTTP[0].Matchers[0].Words[0])
	require.Equal(t, map[string]interface{}{"shared": "original"}, original.Variables.GetAll())
}
