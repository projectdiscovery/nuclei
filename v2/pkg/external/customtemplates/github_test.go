package customtemplates

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestDownloadCustomTemplatesFromGitHub(t *testing.T) {
	gologger.DefaultLogger.SetWriter(&testutils.NoopWriter{})

	templatesDirectory, err := os.MkdirTemp("", "template-custom-*")
	require.Nil(t, err, "could not create temp directory")
	defer os.RemoveAll(templatesDirectory)

	options := testutils.DefaultOptions
	options.GithubTemplateRepo = []string{"projectdiscovery/nuclei-templates", "ehsandeep/nuclei-templates"}

	customTemplates := ParseCustomTemplates(options)

	for _, ct := range *customTemplates {
		ct.Download(templatesDirectory, context.Background())
	}

	require.DirExists(t, filepath.Join(templatesDirectory, "github", "nuclei-templates"), "cloned directory does not exists")
	require.DirExists(t, filepath.Join(templatesDirectory, "github", "nuclei-templates-ehsandeep"), "cloned directory does not exists")
}
