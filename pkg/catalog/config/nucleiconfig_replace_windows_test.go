package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReplaceTemplatesConfigFile(t *testing.T) {
	for _, targetExists := range []bool{false, true} {
		name := "creates"
		if targetExists {
			name = "replaces"
		}
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "config.json")
			if targetExists {
				if err := os.WriteFile(target, []byte("previous"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			temporary := filepath.Join(directory, "config.tmp")
			if err := os.WriteFile(temporary, []byte("current"), 0o600); err != nil {
				t.Fatal(err)
			}

			if err := replaceTemplatesConfigFile(temporary, target); err != nil {
				t.Fatal(err)
			}
			contents, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if string(contents) != "current" {
				t.Fatalf("expected replacement contents, got %q", contents)
			}
		})
	}
}
