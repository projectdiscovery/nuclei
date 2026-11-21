package core //nolint:testpackage // it uses the unexported test helpers of the package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// savedWhenInFlight polls the progress of templateID until exactly the want
// positions are in flight, and returns a copy of the progress as an interrupt
// would save it.
func savedWhenInFlight(t *testing.T, cfg *types.ResumeCfg, templateID string, want ...uint32) *types.ResumeCfg {
	t.Helper()

	var got []uint32

	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		saved := cfg.Clone()

		info, ok := saved.Current[templateID]
		if !ok {
			continue
		}

		got = slices.Sorted(maps.Keys(info.InFlight))
		if slices.Equal(got, want) {
			return saved
		}
	}

	t.Fatalf("positions in flight of %s = %v, want %v", templateID, got, want)

	return nil
}

// pausingTargets waits before yielding the input at position pauseAt until
// resume is closed.
type pausingTargets struct {
	*fakeTargetProvider

	pauseAt        int
	paused, resume chan struct{}
}

func (p *pausingTargets) Iterate(callback func(*contextargs.MetaInput) bool) {
	for i, value := range p.values {
		if i == p.pauseAt {
			close(p.paused)
			<-p.resume
		}

		if !callback(value) {
			return
		}
	}
}

// savedBetween runs a template-spray scan of inputs from cfg, and returns the
// progress saved while the scan waits before pauseAt with every earlier target
// done, which is when an interrupt finds no target in flight.
func savedBetween(t *testing.T, cfg *types.ResumeCfg, inputs []string, pauseAt int) *types.ResumeCfg {
	t.Helper()

	var (
		runsMu sync.Mutex
		runs   []string
	)

	engine, _ := newTaskEngine(scanstrategy.TemplateSpray, nil, nil, cfg)
	targets := &pausingTargets{
		fakeTargetProvider: targetsOf(inputs...),
		pauseAt:            pauseAt,
		paused:             make(chan struct{}),
		resume:             make(chan struct{}),
	}
	resume := sync.OnceFunc(func() { close(targets.resume) })
	t.Cleanup(resume)

	done := make(chan struct{})

	go func() {
		defer close(done)

		tpls := []*templates.Template{resumeTemplate(&recordingExecuter{path: resumeTemplateID, mu: &runsMu, runs: &runs})}

		engine.ExecuteScanWithOpts(context.Background(), tpls, targets, true)
	}()

	select {
	case <-targets.paused:
	case <-time.After(10 * time.Second):
		t.Fatalf("the scan never reached position %d", pauseAt)
	}

	saved := savedWhenInFlight(t, cfg, resumeTemplateID)

	resume()
	<-done

	return saved
}

// A scan interrupted after one target ended and before the next one started has
// no target in flight. Its resumed scan runs every target: the saved progress
// doesn't say how far the scan got.
//
//nolint:paralleltest // each scan resets the shared HTTP responses of the process
func TestResumeBetweenTargets(t *testing.T) {
	inputs := []string{"a", "b", "c"}
	saved := savedBetween(t, types.NewResumeCfg(), inputs, 1)
	assert.False(t, saved.Current[resumeTemplateID].Completed, "completed")

	got := resumedRuns(resumeFromSaved(t, saved), inputs, nil)
	assert.ElementsMatch(t, inputs, got, "targets of the resumed scan")
}

// A resumed scan interrupted while it still skips the targets before the
// position it resumes from has nothing in flight either, and the next resumed
// scan must still reach every target.
//
//nolint:paralleltest // each scan resets the shared HTTP responses of the process
func TestResumeAgainWhileSkipping(t *testing.T) {
	inputs := []string{"a", "b", "c", "d"}

	first := types.NewResumeCfg()
	//nolint:exhaustruct,exhaustruct_v5 // zero values are the defaults
	first.Current[resumeTemplateID] = &types.ResumeInfo{InFlight: map[uint32]struct{}{2: {}}}

	// the second scan skips a, the targets before c, and is saved before b
	saved := savedBetween(t, resumeFromSaved(t, first), inputs, 1)
	require.Empty(t, saved.Current[resumeTemplateID].InFlight)

	got := resumedRuns(resumeFromSaved(t, saved), inputs, nil)
	assert.ElementsMatch(t, inputs, got, "targets of the third scan")
}
