package runner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func TestTemplateVersionInfoIgnoresLegacyDiscoverySource(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "system", config.BinaryName, config.NucleiTemplatesDirName)
	cfg := &config.Config{}
	cfg.SetStateDir(filepath.Join(dir, "state"))

	state, err := json.Marshal(map[string]string{
		"nuclei-templates-directory":        root,
		"nuclei-templates-directory-source": "xdg-system",
		"nuclei-templates-version":          "v1.2.3",
		"nuclei-templates-latest-version":   "v99.0.0",
	})
	if err != nil {
		t.Fatalf("marshal templates state: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.GetTemplatesStateFilePath()), 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	if err := os.WriteFile(cfg.GetTemplatesStateFilePath(), state, 0o600); err != nil {
		t.Fatalf("write templates state: %v", err)
	}
	if err := cfg.ReadTemplatesConfig(); err != nil {
		t.Fatalf("read templates state: %v", err)
	}

	info := templateVersionInfo(cfg, nil)
	if !strings.Contains(info, "v1.2.3") || !strings.Contains(info, "outdated") {
		t.Fatalf("template version info = %q, want normal version comparison", info)
	}
	if strings.Contains(info, "package-managed") {
		t.Fatalf("template version info retained discovery ownership: %q", info)
	}
}
