package types

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

func TestGeneratedResumePathsUseStateDirectory(t *testing.T) {
	stateDir := t.TempDir()
	oldStateDir := config.DefaultConfig.GetStateDir()
	config.DefaultConfig.SetStateDir(stateDir)
	t.Cleanup(func() { config.DefaultConfig.SetStateDir(oldStateDir) })

	resumePath := DefaultResumeFilePath()
	if filepath.Dir(resumePath) != stateDir || !strings.HasPrefix(filepath.Base(resumePath), "resume-") {
		t.Fatalf("resume path = %q, want generated file under %q", resumePath, stateDir)
	}
	if got, want := DefaultCrashResumeFilePath("dump"), filepath.Join(stateDir, "crash-resume-file-dump.dump"); got != want {
		t.Fatalf("crash resume path = %q, want %q", got, want)
	}
}
