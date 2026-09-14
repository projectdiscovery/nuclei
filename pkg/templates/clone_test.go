package templates

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
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

func TestCloneTemplatePreservesMutableAliases(t *testing.T) {
	sharedMap := map[string]interface{}{"value": "original"}
	sharedSlice := []interface{}{"original"}
	original := &Template{
		Constants: map[string]interface{}{
			"map":         sharedMap,
			"first-slice": sharedSlice,
			"next-slice":  sharedSlice,
		},
	}
	original.Variables.InsertionOrderedStringMap = *utils.NewEmptyInsertionOrderedStringMap(1)
	original.Variables.Set("map", sharedMap)

	cloned := cloneTemplate(original)
	clonedMap := cloned.Constants["map"].(map[string]interface{})
	clonedVariableMap := cloned.Variables.GetAll()["map"].(map[string]interface{})
	clonedFirstSlice := cloned.Constants["first-slice"].([]interface{})
	clonedNextSlice := cloned.Constants["next-slice"].([]interface{})

	clonedMap["value"] = "changed"
	clonedFirstSlice[0] = "changed"

	require.Equal(t, "changed", clonedVariableMap["value"])
	require.Equal(t, "changed", clonedNextSlice[0])
	require.Equal(t, "original", sharedMap["value"])
	require.Equal(t, "original", sharedSlice[0])
}

func TestCloneTemplateHandlesMutableCycles(t *testing.T) {
	cyclicMap := make(map[string]interface{})
	cyclicMap["self"] = cyclicMap
	cyclicSlice := make([]interface{}, 1)
	cyclicSlice[0] = cyclicSlice
	original := &Template{Constants: map[string]interface{}{
		"map":   cyclicMap,
		"slice": cyclicSlice,
	}}

	cloned := cloneTemplate(original)
	clonedMap := cloned.Constants["map"].(map[string]interface{})
	clonedMap["self"].(map[string]interface{})["changed"] = true
	clonedSlice := cloned.Constants["slice"].([]interface{})
	clonedSlice[0].([]interface{})[0] = "changed"

	require.True(t, clonedMap["changed"].(bool))
	require.Equal(t, "changed", clonedSlice[0])
	require.NotContains(t, cyclicMap, "changed")
	require.IsType(t, []interface{}{}, cyclicSlice[0])
}
