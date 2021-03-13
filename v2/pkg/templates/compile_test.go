package templates

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMatchTemplateWithTags(t *testing.T) {
	err := matchTemplateWithTags("php,linux,symfony", "", []string{"php"})
	require.Nil(t, err, "could not get php tag from input slice")

	err = matchTemplateWithTags("lang:php,os:linux,cms:symfony", "", []string{"cms:symfony"})
	require.Nil(t, err, "could not get php tag from input key value")

	err = matchTemplateWithTags("lang:php,os:linux,symfony", "", []string{"cms:symfony"})
	require.NotNil(t, err, "could get key value tag from input key value")

	err = matchTemplateWithTags("lang:php,os:linux,cms:jira", "", []string{"cms:symfony"})
	require.NotNil(t, err, "could get key value tag from input key value")

	t.Run("space", func(t *testing.T) {
		err = matchTemplateWithTags("lang:php, os:linux, cms:symfony", "", []string{"cms:symfony"})
		require.Nil(t, err, "could get key value tag from input key value with space")
	})

	t.Run("comma-tags", func(t *testing.T) {
		err = matchTemplateWithTags("lang:php,os:linux,cms:symfony", "", []string{"test,cms:symfony"})
		require.Nil(t, err, "could get key value tag from input key value with comma")
	})

	t.Run("severity", func(t *testing.T) {
		err = matchTemplateWithTags("lang:php,os:linux,cms:symfony", "low", []string{"low"})
		require.Nil(t, err, "could get key value tag for severity")
	})

	t.Run("blank-tags", func(t *testing.T) {
		err = matchTemplateWithTags("", "low", []string{"jira"})
		require.NotNil(t, err, "could get value tag for blank severity")
	})
}
