package runner

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/formatter"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

type ignoreFileLogRecord struct {
	message string
	level   levels.Level
}

type ignoreFileLogWriter struct {
	records []ignoreFileLogRecord
}

func (w *ignoreFileLogWriter) Write(data []byte, level levels.Level) {
	w.records = append(w.records, ignoreFileLogRecord{message: string(data), level: level})
}

func newIgnoreFileTestRunner(t *testing.T, root string, writer *ignoreFileLogWriter) *Runner {
	t.Helper()

	cfg := config.DefaultConfig
	oldRoot := cfg.TemplatesDirectory
	t.Cleanup(func() { cfg.SetTemplatesDir(oldRoot) })
	cfg.SetTemplatesDir(root)

	logger := &gologger.Logger{}
	logger.SetFormatter(formatter.NewCLI(false))
	logger.SetWriter(writer)
	logger.SetMaxLevel(levels.LevelWarning)

	options := types.DefaultOptions()
	options.Logger = logger
	return &Runner{options: options, Logger: logger}
}

func TestLoadIgnoreFileWarnsAndContinuesWhenActiveFileIsMissing(t *testing.T) {
	root := t.TempDir()
	writer := &ignoreFileLogWriter{}
	runner := newIgnoreFileTestRunner(t, root, writer)

	require.NoError(t, runner.loadIgnoreFile())
	require.Empty(t, runner.options.ExcludeTags)
	require.Empty(t, runner.options.ExcludedTemplates)
	require.Len(t, writer.records, 1)
	require.Equal(t, levels.LevelWarning, writer.records[0].level)
	require.Contains(t, writer.records[0].message, strconv.Quote(filepath.Join(root, config.NucleiIgnoreFileName)))
	require.Contains(t, writer.records[0].message, "continuing without ignore exclusions")
}

func TestLoadIgnoreFileRejectsCorruptActiveFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, config.NucleiIgnoreFileName)
	require.NoError(t, os.WriteFile(path, []byte("tags: ["), 0o600))
	writer := &ignoreFileLogWriter{}
	runner := newIgnoreFileTestRunner(t, root, writer)

	err := runner.loadIgnoreFile()
	require.ErrorContains(t, err, "error parsing")
	require.ErrorContains(t, err, strconv.Quote(path))
	require.Empty(t, writer.records)
}
