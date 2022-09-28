package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/stretchr/testify/require"
)

func TestDownloadCustomTemplates(t *testing.T) {
	gologger.DefaultLogger.SetWriter(&testutils.NoopWriter{})

	templatesDirectory, err := os.MkdirTemp("", "template-custom-*")
	require.Nil(t, err, "could not create temp directory")
	defer os.RemoveAll(templatesDirectory)

	options := testutils.DefaultOptions
	options.GithubTemplateRepo = []string{"projectdiscovery/nuclei-templates", "ehsandeep/nuclei-templates"}
	r := &Runner{templatesConfig: &config.Config{TemplatesDirectory: templatesDirectory}, options: options}

	r.parseCustomTemplates()

	r.downloadCustomTemplates(context.Background())

	require.DirExists(t, filepath.Join(templatesDirectory, "github", "nuclei-templates"), "cloned directory does not exists")
	require.DirExists(t, filepath.Join(templatesDirectory, "github", "nuclei-templates-ehsandeep"), "cloned directory does not exists")
}
