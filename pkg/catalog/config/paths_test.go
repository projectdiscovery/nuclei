package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/adrg/xdg"
)

func TestXDGConfigPaths(t *testing.T) {
	if got, want := defaultConfigDir(), filepath.Join(xdg.ConfigHome, BinaryName); got != want {
		t.Fatalf("default config directory = %q, want %q", got, want)
	}

	if got, want := (&Config{}).GetCacheDir(), filepath.Join(xdg.CacheHome, BinaryName); got != want {
		t.Fatalf("cache directory = %q, want %q", got, want)
	}

	if got, want := (&Config{}).GetStateDir(), filepath.Join(xdg.StateHome, BinaryName); got != want {
		t.Fatalf("state directory = %q, want %q", got, want)
	}
}

func TestSelectXDGTemplateRoot(t *testing.T) {
	t.Run("user data wins", func(t *testing.T) {
		dir := t.TempDir()
		dataHome := filepath.Join(dir, "user")
		userRoot := filepath.Join(dataHome, BinaryName, NucleiTemplatesDirName)
		if err := os.MkdirAll(userRoot, 0o700); err != nil {
			t.Fatalf("create user root: %v", err)
		}
		systemRoot := filepath.Join(dir, "system", BinaryName, NucleiTemplatesDirName)
		if err := os.MkdirAll(systemRoot, 0o755); err != nil {
			t.Fatalf("create system root: %v", err)
		}

		root, err := selectXDGTemplateRoot(dataHome, []string{filepath.Join(dir, "system")})
		if err != nil {
			t.Fatalf("select root: %v", err)
		}
		if root != userRoot {
			t.Fatalf("root = %q, want %q", root, userRoot)
		}
	})

	t.Run("first system directory wins", func(t *testing.T) {
		dir := t.TempDir()
		firstDir := filepath.Join(dir, "first")
		secondDir := filepath.Join(dir, "second")
		for _, base := range []string{firstDir, secondDir} {
			if err := os.MkdirAll(filepath.Join(base, BinaryName, NucleiTemplatesDirName), 0o755); err != nil {
				t.Fatalf("create system root: %v", err)
			}
		}

		root, err := selectXDGTemplateRoot(filepath.Join(dir, "user"), []string{firstDir, secondDir})
		if err != nil {
			t.Fatalf("select root: %v", err)
		}
		want := filepath.Join(firstDir, BinaryName, NucleiTemplatesDirName)
		if root != want {
			t.Fatalf("root = %q, want %q", root, want)
		}
	})

	t.Run("missing roots select user installation target", func(t *testing.T) {
		dataHome := filepath.Join(t.TempDir(), "user")
		root, err := selectXDGTemplateRoot(dataHome, nil)
		if err != nil {
			t.Fatalf("select root: %v", err)
		}
		want := filepath.Join(dataHome, BinaryName, NucleiTemplatesDirName)
		if root != want {
			t.Fatalf("root = %q, want %q", root, want)
		}
	})

	t.Run("relative user data home is rejected", func(t *testing.T) {
		if _, err := selectXDGTemplateRoot("relative", nil); err == nil {
			t.Fatal("relative XDG data home was accepted")
		}
	})
}
