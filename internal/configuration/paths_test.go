package configuration

import (
	"os"
	"path/filepath"
	"testing"

	catalogconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func TestUnixSystemConfigFilePath(t *testing.T) {
	for _, goos := range []string{"aix", "darwin", "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "solaris"} {
		if got, want := unixSystemConfigFilePath(goos), "/etc/nuclei/config.yaml"; got != want {
			t.Fatalf("unix system config for %s = %q, want %q", goos, got, want)
		}
	}
	for _, goos := range []string{"windows", "plan9", "js"} {
		if got := unixSystemConfigFilePath(goos); got != "" {
			t.Fatalf("system config for %s = %q, want empty", goos, got)
		}
	}
}

func TestPrepareUserConfigFile(t *testing.T) {
	dir := t.TempDir()
	defaultConfigFile := filepath.Join(dir, "default", catalogconfig.CLIConfigFileName)
	customConfigFile := filepath.Join(dir, "custom", catalogconfig.CLIConfigFileName)
	if err := os.MkdirAll(filepath.Dir(defaultConfigFile), 0o700); err != nil {
		t.Fatalf("create default config directory: %v", err)
	}
	if err := os.WriteFile(defaultConfigFile, []byte("value: inherited\n"), 0o600); err != nil {
		t.Fatalf("write default config: %v", err)
	}

	if err := prepareUserConfigFile(customConfigFile, defaultConfigFile); err != nil {
		t.Fatalf("prepare user config file: %v", err)
	}
	data, err := os.ReadFile(customConfigFile)
	if err != nil {
		t.Fatalf("read inherited config: %v", err)
	}
	if got, want := string(data), "value: inherited\n"; got != want {
		t.Fatalf("inherited config = %q, want %q", got, want)
	}

	if err := os.WriteFile(defaultConfigFile, []byte("value: changed\n"), 0o600); err != nil {
		t.Fatalf("update default config: %v", err)
	}
	if err := prepareUserConfigFile(customConfigFile, defaultConfigFile); err != nil {
		t.Fatalf("prepare existing user config: %v", err)
	}
	data, err = os.ReadFile(customConfigFile)
	if err != nil {
		t.Fatalf("read existing user config: %v", err)
	}
	if got, want := string(data), "value: inherited\n"; got != want {
		t.Fatalf("existing user config = %q, want %q", got, want)
	}

	missingConfigFile := filepath.Join(dir, "missing-custom", catalogconfig.CLIConfigFileName)
	if err := prepareUserConfigFile(missingConfigFile, filepath.Join(dir, "missing-default.yaml")); err != nil {
		t.Fatalf("prepare config without default source: %v", err)
	}
	if _, err := os.Stat(missingConfigFile); !os.IsNotExist(err) {
		t.Fatalf("missing default source created user config: %v", err)
	}
}
