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

func TestDownloadCustomTemplateRepo(t *testing.T) {
	gologger.DefaultLogger.SetWriter(&testutils.NoopWriter{})

	templatesDirectory, err := os.MkdirTemp("", "template-custom-*")
	require.Nil(t, err, "could not create temp directory")
	defer os.RemoveAll(templatesDirectory)

	r := &Runner{templatesConfig: &config.Config{TemplatesDirectory: templatesDirectory}, options: testutils.DefaultOptions}

	msg, err := r.downloadCustomTemplateRepo("projectdiscovery/nuclei-templates", context.Background())
	require.Nil(t, err, "failed to clone the repo")
	require.Contains(t, msg, "successfully", "failed to clone the repo")
	require.DirExists(t, filepath.Join(templatesDirectory, "github", "nuclei-templates"), "cloned directory does not exists")

	msg, err = r.downloadCustomTemplateRepo("ehsandeep/nuclei-templates", context.Background())
	require.Nil(t, err, "failed to clone the repo")
	require.Contains(t, msg, "successfully", "failed to clone the repo")
	require.DirExists(t, filepath.Join(templatesDirectory, "github", "nuclei-templates-ehsandeep"), "cloned directory does not exists")
}
