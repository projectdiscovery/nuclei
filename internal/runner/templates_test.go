package runner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/stretchr/testify/require"
)

const listedTemplateYAML = `id: listed-template
info:
  name: Listed Template
  author: pdteam
  severity: info
  tags: listing
http:
  - method: GET
    path:
      - "{{BaseURL}}"
`

func TestTemplateListWritesJSONLines(t *testing.T) {
	root := t.TempDir()
	cfg := config.DefaultConfig
	oldRoot := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(oldRoot) })
	cfg.SetTemplatesDir(root)

	path := filepath.Join(root, "http", "listed-template.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(listedTemplateYAML), 0o600))

	writer := &ignoreFileLogWriter{}
	logger := &gologger.Logger{}
	logger.SetFormatter(formatter.NewCLI(true))
	logger.SetWriter(writer)
	logger.SetMaxLevel(levels.LevelInfo)

	options := testutils.DefaultOptions.Copy()
	options.ExecutionId = t.Name()
	options.Logger = logger
	options.Templates = []string{path}
	options.TemplateList = true
	options.JSONL = true
	testutils.Init(options)
	t.Cleanup(func() { testutils.Cleanup(options) })

	executerOpts := testutils.NewMockExecuterOptions(options, nil)
	executerOpts.Parser = templates.NewParser()
	store, err := loader.New(loader.NewConfig(options, disk.NewCatalog(root), executerOpts))
	require.NoError(t, err)
	require.NoError(t, store.LoadTemplatesOnlyMetadata())

	require.Len(t, store.Templates(), 1)

	r := &Runner{options: options, Logger: logger}
	r.listAvailableStoreTemplates(store)

	require.Len(t, writer.records, 1, "JSONL output carries no banner line")
	var listed map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(writer.records[0].message)), &listed))
	require.Equal(t, "listed-template", listed["template-id"])
	require.Equal(t, filepath.Join("http", "listed-template.yaml"), listed["template"])
	require.Equal(t, "Listed Template", listed["info"].(map[string]any)["name"])
}
