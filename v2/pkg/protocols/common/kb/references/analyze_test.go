package references

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/stretchr/testify/require"
)

func TestAnalyzeReferences(t *testing.T) {
	dependency := AnalyzeReferences([]*templates.Template{
		{ID: "main-template"},
		{ID: "sub-template", Path: "sub-template", Data: "kb_get(\"main-template:value\")"},
	})
	require.Equal(t, map[string][]ValueDependency{"main-template": {{Path: "sub-template", Value: "value", FullReference: "main-template:value"}}}, dependency.Dependencies, "could not get correct depdedency")
	require.Equal(t, map[string]struct{}{"main-template": {}, "sub-template": {}}, dependency.References, "could not get correct references")

	t.Run("sub-sub-templates", func(t *testing.T) {
		dependency := AnalyzeReferences([]*templates.Template{
			{ID: "main-template"},
			{ID: "sub-template", Path: "sub-template", Data: "kb_get(\"main-template:value\")"},
			{ID: "sub-sub-template", Path: "sub-sub-template", Data: "kb_get(\"sub-template:test\")"},
		})
		require.Equal(t, map[string][]ValueDependency{"main-template": {{Path: "sub-template", Value: "value", FullReference: "main-template:value"}}, "sub-template": {{Path: "sub-sub-template", Value: "test", FullReference: "sub-template:test"}}}, dependency.Dependencies, "could not get correct depdedency")
	})
}
