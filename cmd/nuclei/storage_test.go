package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

const inlineSecretsFatalChildEnv = "NUCLEI_INLINE_SECRETS_FATAL_CHILD"

func TestValidateResetPathRejectsBroadTargets(t *testing.T) {
	if err := validateResetPath(""); err == nil {
		t.Fatal("empty reset path was accepted")
	}
	if err := validateResetPath(string(filepath.Separator)); err == nil {
		t.Fatal("filesystem root reset path was accepted")
	}
	if err := validateResetPath(filepath.Join(string(filepath.Separator), "var")); err == nil {
		t.Fatal("broad top-level reset path was accepted")
	}
	if err := validateResetPath(os.TempDir()); err == nil {
		t.Fatal("system temporary directory reset path was accepted")
	}
	if cwd, err := os.Getwd(); err == nil {
		if err := validateResetPath(cwd); err == nil {
			t.Fatal("current working directory reset path was accepted")
		}
	}
	if homeDir, err := os.UserHomeDir(); err == nil {
		if err := validateResetPath(homeDir); err == nil {
			t.Fatal("user home reset path was accepted")
		}
	}
	if err := validateResetPath(t.TempDir()); err != nil {
		t.Fatalf("scoped reset path was rejected: %v", err)
	}
}

func TestRemoveResetPathsValidatesAllTargetsBeforeDeletion(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatalf("create config directory: %v", err)
	}

	paths := []resetPath{
		{name: "config", path: configDir},
		{name: "unsafe", path: string(filepath.Separator)},
	}
	if err := removeResetPaths(paths); err == nil {
		t.Fatal("unsafe reset target was accepted")
	}
	if _, err := os.Stat(configDir); err != nil {
		t.Fatalf("config directory was removed before validation completed: %v", err)
	}
}

func TestCleanupInlineSecretsDirsRemovesPrivateDirectory(t *testing.T) {
	secretsDir := filepath.Join(t.TempDir(), "nuclei-secrets-run")
	if err := os.Mkdir(secretsDir, 0o700); err != nil {
		t.Fatalf("create inline secrets directory: %v", err)
	}
	secretsPath := filepath.Join(secretsDir, "inline-secrets.yaml")
	if err := os.WriteFile(secretsPath, []byte("static: []\n"), 0o600); err != nil {
		t.Fatalf("write inline secrets file: %v", err)
	}

	inlineSecretsTempMu.Lock()
	previous := inlineSecretsTempDir
	inlineSecretsTempDir = secretsDir
	inlineSecretsTempMu.Unlock()
	t.Cleanup(func() {
		inlineSecretsTempMu.Lock()
		inlineSecretsTempDir = previous
		inlineSecretsTempMu.Unlock()
	})

	cleanupInlineSecretsDirs()
	if _, err := os.Stat(secretsDir); !os.IsNotExist(err) {
		t.Fatalf("inline secrets directory still exists: %v", err)
	}
}

func TestCleanupInlineSecretsDirsIsConcurrentSafe(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "nuclei-secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create inline secrets directory: %v", err)
	}

	inlineSecretsTempMu.Lock()
	previous := inlineSecretsTempDir
	inlineSecretsTempDir = dir
	inlineSecretsTempMu.Unlock()
	t.Cleanup(func() {
		inlineSecretsTempMu.Lock()
		inlineSecretsTempDir = previous
		inlineSecretsTempMu.Unlock()
	})

	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			cleanupInlineSecretsDirs()
		}()
	}
	close(start)
	wg.Wait()

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("inline secrets directory still exists: %s: %v", dir, err)
	}
}

func TestReadConfigFatalCleansInlineSecretsDirectory(t *testing.T) {
	if os.Getenv(inlineSecretsFatalChildEnv) == "1" {
		options = &types.Options{Logger: gologger.DefaultLogger}
		os.Args = []string{
			os.Args[0],
			"-profile", os.Getenv("NUCLEI_TEST_PROFILE"),
			"-secret-file", os.Getenv("NUCLEI_TEST_MISSING_SECRET"),
			"-disable-update-check",
		}
		readConfig()
		os.Exit(0)
	}

	root := t.TempDir()
	profilePath := filepath.Join(root, "profile.yaml")
	if err := os.WriteFile(profilePath, []byte("secrets:\n  static: []\n"), 0o600); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	missingSecret := filepath.Join(root, "missing-secrets.yaml")
	tempRoot := filepath.Join(root, "tmp")
	if err := os.Mkdir(tempRoot, 0o700); err != nil {
		t.Fatalf("create temporary root: %v", err)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestReadConfigFatalCleansInlineSecretsDirectory$", "-test.count=1")
	cmd.Env = isolatedNucleiStorageEnv(root, tempRoot,
		inlineSecretsFatalChildEnv+"=1",
		"NUCLEI_TEST_PROFILE="+profilePath,
		"NUCLEI_TEST_MISSING_SECRET="+missingSecret,
	)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("child process did not exit on the missing secrets file")
	}
	if !bytes.Contains(output, []byte("Secrets file")) || !bytes.Contains(output, []byte("does not exist")) {
		t.Fatalf("child did not reach the missing secrets file failure:\n%s", output)
	}

	matches, err := filepath.Glob(filepath.Join(tempRoot, "nuclei-secrets-*"))
	if err != nil {
		t.Fatalf("list inline secrets directories: %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("inline secrets directories remain after fatal exit: %v", matches)
	}
}

func isolatedNucleiStorageEnv(root, tempRoot string, extra ...string) []string {
	env := append(os.Environ(),
		"TMPDIR="+tempRoot,
		"TMP="+tempRoot,
		"TEMP="+tempRoot,
		"XDG_CONFIG_HOME="+filepath.Join(root, "config"),
		"XDG_STATE_HOME="+filepath.Join(root, "state"),
		"XDG_CACHE_HOME="+filepath.Join(root, "cache"),
		"XDG_DATA_HOME="+filepath.Join(root, "data"),
		"NUCLEI_CONFIG_DIR="+filepath.Join(root, "config", "nuclei"),
	)
	return append(env, extra...)
}
