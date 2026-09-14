package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/internal/configuration"
	catalogconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func TestAuthValueIsCLIOnly(t *testing.T) {
	oldConfigHome := xdg.ConfigHome
	oldConfigDirs := xdg.ConfigDirs
	t.Cleanup(func() {
		xdg.ConfigHome = oldConfigHome
		xdg.ConfigDirs = oldConfigDirs
	})

	const apiKey = "12345678-1234-1234-1234-123456789012"
	tests := []struct {
		name string
		args func(string) []string
		file string
		want string
	}{
		{name: "explicit config", args: func(path string) []string { return []string{"-config=" + path} }, file: "auth: true\n"},
		{name: "profile", args: func(path string) []string { return []string{"-profile=" + path} }, file: "auth: " + apiKey + "\n"},
		{name: "CLI", args: func(string) []string { return []string{"-auth=" + apiKey} }, want: apiKey},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			xdg.ConfigHome = filepath.Join(dir, "config-home")
			xdg.ConfigDirs = nil

			selectedPath := filepath.Join(dir, "selected.yaml")
			if test.file != "" {
				if err := os.WriteFile(selectedPath, []byte(test.file), 0o600); err != nil {
					t.Fatalf("write selected configuration: %v", err)
				}
			}

			var auth string
			var selected configuration.Selection
			flagSet := goflags.NewFlagSet()
			flagSet.DynamicVar(&auth, "auth", "true", "")
			flagSet.StringVar(&selected.Config, "config", "", "")
			flagSet.StringVar(&selected.Profile, "profile", "", "")

			cfg := &catalogconfig.Config{Logger: gologger.DefaultLogger}
			cfg.SetConfigDir(filepath.Join(xdg.ConfigHome, catalogconfig.BinaryName))
			warnings, err := configuration.Load(cfg, flagSet, &selected, func(path string) (string, error) {
				return path, nil
			}, test.args(selectedPath)...)
			if err != nil {
				t.Fatalf("load configuration: %v", err)
			}
			if len(warnings) != 0 {
				t.Fatalf("configuration warnings: %v", warnings)
			}

			if got := cliOnlyDynamicValue(flagSet, "auth", auth); got != test.want {
				t.Fatalf("auth value = %q, want %q", got, test.want)
			}
		})
	}
}
