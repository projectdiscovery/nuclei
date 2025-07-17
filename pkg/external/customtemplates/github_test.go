package customtemplates

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/testutils"
	"github.com/stretchr/testify/require"
)

// stdoutWriter adapts os.Stdout to the gologger writer interface
type stdoutWriter struct{}

func (w *stdoutWriter) Write(data []byte, level levels.Level) {
	os.Stdout.Write(data)
}

func TestDownloadCustomTemplatesFromGitHub(t *testing.T) {
	// if osutils.IsOSX() {
	// 	t.Skip("skipping on macos due to unknown failure (works locally)")
	// }

	gologger.DefaultLogger.SetWriter(&stdoutWriter{})
	gologger.DefaultLogger.SetMaxLevel(levels.LevelDebug)

	templatesDirectory := t.TempDir()
	config.DefaultConfig.SetTemplatesDir(templatesDirectory)

	options := testutils.DefaultOptions
	options.GitHubTemplateRepo = []string{"projectdiscovery/nuclei-templates-test"}

	ctm, err := NewCustomTemplatesManager(options)
	require.Nil(t, err, "could not create custom templates manager")

	ctm.Download(context.Background())

	require.DirExists(t, filepath.Join(templatesDirectory, "github", "projectdiscovery", "nuclei-templates-test"), "cloned directory does not exists")
}
