package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestMatchTemplateWithTags(t *testing.T) {
	err := matchTemplateWithTags("php,linux,symfony", &types.Options{Tags: []string{"php"}})
	require.Nil(t, err, "could not get php tag from input slice")

	err = matchTemplateWithTags("lang:php,os:linux,cms:symfony", &types.Options{Tags: []string{"cms:symfony"}})
	require.Nil(t, err, "could not get php tag from input key value")

	err = matchTemplateWithTags("lang:php,os:linux,symfony", &types.Options{Tags: []string{"cms:symfony"}})
	require.NotNil(t, err, "could get key value tag from input key value")

	err = matchTemplateWithTags("lang:php,os:linux,cms:jira", &types.Options{Tags: []string{"cms:symfony"}})
	require.NotNil(t, err, "could get key value tag from input key value")

	t.Run("space", func(t *testing.T) {
		err = matchTemplateWithTags("lang:php, os:linux, cms:symfony", &types.Options{Tags: []string{"cms:symfony"}})
		require.Nil(t, err, "could get key value tag from input key value with space")
	})

	t.Run("comma-tags", func(t *testing.T) {
		err = matchTemplateWithTags("lang:php,os:linux,cms:symfony", &types.Options{Tags: []string{"test,cms:symfony"}})
		require.Nil(t, err, "could get key value tag from input key value with comma")
	})
}
