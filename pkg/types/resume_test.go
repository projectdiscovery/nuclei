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

// A template saved with nothing in flight has no position to resume from, so
// Compile must not skip any target of it.
func TestCompileWithNothingInFlight(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		inFlight map[uint32]struct{}
		want     uint32
	}{
		{name: "nil", inFlight: nil, want: 0},
		{name: "empty", inFlight: map[uint32]struct{}{}, want: 0},
		{name: "in flight", inFlight: map[uint32]struct{}{3: {}, 5: {}}, want: 3},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := NewResumeCfg()
			//nolint:exhaustruct,exhaustruct_v5 // zero values are the defaults
			cfg.ResumeFrom["probe"] = &ResumeInfo{InFlight: test.inFlight}
			cfg.Compile()

			if got := cfg.ResumeFrom["probe"].GetSkipUnder(); got != test.want {
				t.Fatalf("SkipUnder = %d, want %d", got, test.want)
			}
		})
	}
}
