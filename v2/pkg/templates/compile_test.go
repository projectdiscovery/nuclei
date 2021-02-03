package templates

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestMatchTemplateWithTags(t *testing.T) {
	templateTags := []interface{}{"php", "linux", "symfony"}

	err := matchTemplateWithTags(templateTags, &types.Options{Tags: []string{"php"}})
	require.Nil(t, err, "could not get php tag from input slice")

	templateTags = []interface{}{"lang:php", "os:linux", "cms:symfony"}

	err = matchTemplateWithTags(templateTags, &types.Options{Tags: []string{"cms:symfony"}})
	require.Nil(t, err, "could not get php tag from input key value")

	templateTags = []interface{}{"lang:php", "os:linux", "symfony"}

	err = matchTemplateWithTags(templateTags, &types.Options{Tags: []string{"cms:symfony"}})
	require.NotNil(t, err, "could get key value tag from input key value")
}
