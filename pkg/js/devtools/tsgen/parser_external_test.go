package tsgen_test

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/js/devtools/tsgen"
)

func TestParseExternalTypes(t *testing.T) {
	t.Parallel()

	ep, err := tsgen.NewEntityParser(filepath.Join("testdata", "external"))
	require.NoError(t, err)
	require.NoError(t, ep.Parse())

	entities := make(map[string]tsgen.Entity)
	for _, e := range ep.GetEntities() {
		entities[e.Name] = e
	}

	// net.Conn is an interface, so it has no fields to describe.
	require.Equal(t, "any | null", entities["Dial"].Function.Returns)
	require.Equal(t, []tsgen.Property{{Name: "Conn", Type: "any", Description: ""}}, entities["Session"].Object.Properties)
	require.NotContains(t, entities, "Conn")

	// url.URL is a struct, so its fields become an interface.
	require.Equal(t, "URL | null", entities["Parse"].Function.Returns)
	require.Equal(t, "interface", entities["URL"].Type)
	require.NotEmpty(t, entities["URL"].Object.Properties)
}
