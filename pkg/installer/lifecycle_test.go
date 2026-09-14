package installer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func TestTemplateRootLifecycleIgnoresLegacyDiscoverySource(t *testing.T) {
	dir := t.TempDir()
	// Keep a backslash in the path so JSON escaping is exercised on all platforms.
	root := filepath.Join(dir, `system\nuclei\nuclei-templates`)
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("create template root: %v", err)
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	state, err := json.Marshal(map[string]string{
		"nuclei-templates-directory":        root,
		"nuclei-templates-directory-source": "xdg-system",
	})
	if err != nil {
		t.Fatalf("marshal templates state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, config.TemplatesStateFileName), state, 0o600); err != nil {
		t.Fatalf("write templates state: %v", err)
	}

	oldConfig := config.DefaultConfig
	cfg := &config.Config{}
	cfg.SetStateDir(stateDir)
	if err := cfg.ReadTemplatesConfig(); err != nil {
		t.Fatalf("read templates state: %v", err)
	}
	config.DefaultConfig = cfg
	t.Cleanup(func() { config.DefaultConfig = oldConfig })

	manager := &TemplateManager{DisablePublicTemplates: true}
	if err := manager.installTemplatesAt(root); err != nil {
		t.Fatalf("install into discovered root: %v", err)
	}
	if err := manager.updateTemplatesAt(root); err != nil {
		t.Fatalf("update discovered root: %v", err)
	}
	if err := manager.writeChecksumFileInDir(root); err != nil {
		t.Fatalf("write discovered-root checksum: %v", err)
	}
	if _, err := os.Stat(config.DefaultConfig.GetChecksumFilePath()); err != nil {
		t.Fatalf("stat discovered-root checksum: %v", err)
	}
}
