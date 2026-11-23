package types

import (
	"maps"
	"path/filepath"
	"slices"
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

// savedState is the progress of one template, as a test writes it.
type savedState struct {
	completed bool
	inFlight  []uint32
}

func (state *savedState) info() *ResumeInfo {
	inFlight := make(map[uint32]struct{}, len(state.inFlight))
	for _, position := range state.inFlight {
		inFlight[position] = struct{}{}
	}

	//nolint:exhaustruct,exhaustruct_v5 // zero values are the defaults
	return &ResumeInfo{Completed: state.completed, InFlight: inFlight}
}

// A saved scan must keep the progress it loaded for the templates it didn't
// start, and for the ones it started without finishing a target. It reports
// what it did for a template with a target in flight or a completed template.
func TestSnapshot(t *testing.T) {
	t.Parallel()

	var (
		done      = &savedState{completed: true, inFlight: nil}
		idle      = &savedState{completed: false, inFlight: nil}
		inFlight2 = &savedState{completed: false, inFlight: []uint32{2}}
		inFlight3 = &savedState{completed: false, inFlight: []uint32{3}}
	)

	tests := []struct {
		name    string
		loaded  *savedState
		current *savedState
		want    *savedState
	}{
		{name: "only loaded", loaded: inFlight2, current: nil, want: inFlight2},
		{name: "only loaded and completed", loaded: done, current: nil, want: done},
		{name: "only current", loaded: nil, current: inFlight3, want: inFlight3},
		{name: "loaded completed, current idle", loaded: done, current: idle, want: done},
		{name: "loaded in flight, current idle", loaded: inFlight2, current: idle, want: inFlight2},
		{name: "loaded in flight, current in flight", loaded: inFlight2, current: inFlight3, want: inFlight3},
		{name: "loaded in flight, current completed", loaded: inFlight2, current: done, want: done},
		{name: "loaded completed, current completed", loaded: done, current: done, want: done},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			cfg := NewResumeCfg()
			if test.loaded != nil {
				cfg.ResumeFrom["probe"] = test.loaded.info()
			}

			if test.current != nil {
				cfg.Current["probe"] = test.current.info()
			}

			cfg.Compile()

			saved := cfg.Snapshot().ResumeFrom
			if len(saved) != 1 || saved["probe"] == nil {
				t.Fatalf("saved templates = %v, want only probe", saved)
			}

			info := saved["probe"]
			if info.Completed != test.want.completed {
				t.Errorf("completed = %t, want %t", info.Completed, test.want.completed)
			}

			if inFlight := slices.Sorted(maps.Keys(info.InFlight)); !slices.Equal(inFlight, test.want.inFlight) {
				t.Errorf("in flight = %v, want %v", inFlight, test.want.inFlight)
			}
		})
	}
}

// Saving must not change the progress that the running scan still uses.
func TestSnapshotLeavesProgressUntouched(t *testing.T) {
	t.Parallel()

	cfg := NewResumeCfg()
	//nolint:exhaustruct,exhaustruct_v5 // zero values are the defaults
	cfg.ResumeFrom["unreached"] = &ResumeInfo{InFlight: map[uint32]struct{}{4: {}}}
	//nolint:exhaustruct,exhaustruct_v5 // zero values are the defaults
	cfg.Current["reached"] = &ResumeInfo{}
	cfg.Compile()

	snapshot := cfg.Snapshot()
	if snapshot.ResumeFrom["unreached"] == nil || snapshot.ResumeFrom["reached"] == nil {
		t.Fatalf("saved progress = %v, want unreached and reached", snapshot.ResumeFrom)
	}

	snapshot.ResumeFrom["unreached"].InFlight[9] = struct{}{}
	snapshot.ResumeFrom["reached"].Completed = true

	if len(cfg.Current) != 1 || cfg.Current["reached"].Completed {
		t.Fatalf("Current changed: %v", cfg.Current)
	}

	if _, ok := cfg.ResumeFrom["unreached"].InFlight[9]; ok || len(cfg.ResumeFrom) != 1 {
		t.Fatalf("ResumeFrom changed: %v", cfg.ResumeFrom)
	}
}
