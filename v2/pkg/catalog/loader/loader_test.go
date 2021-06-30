package loader

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/stretchr/testify/require"
)

func TestLoadTemplates(t *testing.T) {
	config, err := config.ReadConfiguration()
	require.Nil(t, err, "could not read configuration")

	store, err := New(&Config{
		Templates: []string{"cves/CVE-2021-21315.yaml"},
	})
	require.Nil(t, err, "could not load templates")
	require.Equal(t, []string{"cves/CVE-2021-21315.yaml"}, store.finalTemplates, "could not get correct templates")

	t.Run("blank", func(t *testing.T) {
		store, err := New(&Config{
			TemplatesDirectory: config.TemplatesDirectory,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{config.TemplatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
	t.Run("only-tags", func(t *testing.T) {
		store, err := New(&Config{
			Tags:               []string{"cves"},
			TemplatesDirectory: config.TemplatesDirectory,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{config.TemplatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
	t.Run("tags-with-path", func(t *testing.T) {
		store, err := New(&Config{
			Tags:               []string{"cves"},
			TemplatesDirectory: config.TemplatesDirectory,
		})
		require.Nil(t, err, "could not load templates")
		require.Equal(t, []string{config.TemplatesDirectory}, store.finalTemplates, "could not get correct templates")
	})
}
