package protocolstate_test

import (
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func restoreTemplatesDir(t *testing.T, templatesDir string) {
	t.Helper()
	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)
	old := config.DefaultConfig.TemplatesDirectory
	config.DefaultConfig.SetTemplatesDir(templatesDir)
	t.Cleanup(func() { config.DefaultConfig.SetTemplatesDir(old) })
}
