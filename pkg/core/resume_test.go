package core //nolint:testpackage // it uses the unexported test helpers of the package

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"maps"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
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

// yieldedTargets closes yielded once the scan has taken every input.
type yieldedTargets struct {
	*fakeTargetProvider

	yielded chan struct{}
}

func (y *yieldedTargets) Iterate(callback func(*contextargs.MetaInput) bool) {
	y.fakeTargetProvider.Iterate(callback)
	close(y.yielded)
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

// A scan cancelled while a target runs leaves that target unfinished and the
// template incomplete, so the resumed scan runs the target and the ones after it.
//
//nolint:paralleltest // each scan resets the shared HTTP responses of the process
func TestResumeAfterCancel(t *testing.T) {
	inputs := []string{"a", "b", "c", "d"}
	cfg := types.NewResumeCfg()
	engine, _ := newTaskEngine(scanstrategy.TemplateSpray, nil, nil, cfg)
	executer := &holdExecuter{hold: "b", held: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(executer.release) })
	t.Cleanup(release)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	targets := &yieldedTargets{fakeTargetProvider: targetsOf(inputs...), yielded: make(chan struct{})}
	done := make(chan struct{})

	go func() {
		defer close(done)

		engine.ExecuteScanWithOpts(ctx, []*templates.Template{resumeTemplate(executer)}, targets, true)
	}()

	for _, reached := range []chan struct{}{executer.held, targets.yielded} {
		select {
		case <-reached:
		case <-time.After(10 * time.Second):
			t.Fatal("the scan never reached b and the end of its targets")
		}
	}

	// every target is dispatched, the others are done, and b is the only one in flight
	savedWhenInFlight(t, cfg, resumeTemplateID, 1)
	cancel()
	release()
	<-done

	saved := cfg.Clone()
	info := saved.Current[resumeTemplateID]
	assert.False(t, info.Completed, "completed")
	assert.Equal(t, []uint32{1}, slices.Sorted(maps.Keys(info.InFlight)), "positions in flight")

	got := resumedRuns(resumeFromSaved(t, saved), inputs, nil)
	assert.ElementsMatch(t, []string{"b", "c", "d"}, got, "targets of the resumed scan")
}

// hostSprayTemplates returns two templates that run on every target: t1 with
// the first executer and t2 with the second.
func hostSprayTemplates(first, second protocols.Executer) []*templates.Template {
	//nolint:exhaustruct_v5 // zero values are the defaults
	return []*templates.Template{
		{ID: "t1", Path: "t1", TotalRequests: 1, Executer: first},
		{ID: "t2", Path: "t2", TotalRequests: 1, Executer: second},
	}
}

// resumedHostSprayRuns returns the template and input pairs that a host-spray
// scan resumed from cfg runs, and checks that its tasks all end.
func resumedHostSprayRuns(t *testing.T, cfg *types.ResumeCfg, inputs []string) []string {
	t.Helper()

	var (
		runsMu sync.Mutex
		runs   []string
	)

	engine, recorder := newTaskEngine(scanstrategy.HostSpray, nil, nil, cfg)
	tpls := hostSprayTemplates(
		&recordingExecuter{path: "t1", mu: &runsMu, runs: &runs},
		&recordingExecuter{path: "t2", mu: &runsMu, runs: &runs},
	)
	engine.ExecuteScanWithOpts(context.Background(), tpls, targetsOf(inputs...), true)
	assert.Equal(t, recorder.total.Load(), recorder.done.Load(), "tasks that didn't end")

	return runs
}

// startHostSprayHeldOnB starts a host-spray run of inputs on engine whose t1
// holds on b, and returns once every target is dispatched and b is the only
// one in flight. The run ends after the returned release and done.
func startHostSprayHeldOnB(
	ctx context.Context, t *testing.T, engine *Engine, inputs []string,
) (func(), chan struct{}) {
	t.Helper()

	var (
		runsMu sync.Mutex
		runs   []string
	)

	executer := &holdExecuter{hold: "b", held: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(executer.release) })
	t.Cleanup(release)

	targets := &yieldedTargets{fakeTargetProvider: targetsOf(inputs...), yielded: make(chan struct{})}
	tpls := hostSprayTemplates(executer, &recordingExecuter{path: "t2", mu: &runsMu, runs: &runs})
	done := make(chan struct{})

	go func() {
		defer close(done)

		engine.ExecuteScanWithOpts(ctx, tpls, targets, true)
	}()

	for _, reached := range []chan struct{}{executer.held, targets.yielded} {
		select {
		case <-reached:
		case <-time.After(10 * time.Second):
			t.Fatal("the scan never reached b and the end of its targets")
		}
	}

	return release, done
}

// A host-spray scan saves the position of the target in flight. Its resumed
// scan runs every template on that target and the ones after it, and skips the
// targets before it.
//
//nolint:paralleltest // each scan resets the shared HTTP responses of the process
func TestHostSprayResume(t *testing.T) {
	inputs := []string{"a", "b", "c"}

	t.Run("interrupted", func(t *testing.T) {
		cfg := types.NewResumeCfg()
		engine, _ := newTaskEngine(scanstrategy.HostSpray, nil, nil, cfg)
		release, done := startHostSprayHeldOnB(t.Context(), t, engine, inputs)
		saved := savedWhenInFlight(t, cfg, hostSprayResumeID, 1)

		release()
		<-done

		got := resumedHostSprayRuns(t, resumeFromSaved(t, saved), inputs)
		assert.ElementsMatch(t, []string{"t1@b", "t2@b", "t1@c", "t2@c"}, got, "pairs of the resumed scan")
	})

	t.Run("cancelled", func(t *testing.T) {
		cfg := types.NewResumeCfg()
		engine, _ := newTaskEngine(scanstrategy.HostSpray, nil, nil, cfg)
		ctx, cancel := context.WithCancel(t.Context())

		defer cancel()

		release, done := startHostSprayHeldOnB(ctx, t, engine, inputs)
		savedWhenInFlight(t, cfg, hostSprayResumeID, 1)
		cancel()
		release()
		<-done

		saved := cfg.Clone()
		require.Contains(t, saved.Current, hostSprayResumeID, "progress of the scan")

		info := saved.Current[hostSprayResumeID]
		assert.False(t, info.Completed, "completed")
		assert.Equal(t, []uint32{1}, slices.Sorted(maps.Keys(info.InFlight)), "positions in flight")

		got := resumedHostSprayRuns(t, resumeFromSaved(t, saved), inputs)
		assert.ElementsMatch(t, []string{"t1@b", "t2@b", "t1@c", "t2@c"}, got, "pairs of the resumed scan")
	})

	t.Run("finished", func(t *testing.T) {
		cfg := types.NewResumeCfg()
		resumedHostSprayRuns(t, cfg, inputs)

		saved := cfg.Clone()
		require.Contains(t, saved.Current, hostSprayResumeID, "progress of the scan")
		assert.True(t, saved.Current[hostSprayResumeID].Completed, "completed")
		assert.Empty(t, saved.Current[hostSprayResumeID].InFlight, "positions in flight")

		got := resumedHostSprayRuns(t, resumeFromSaved(t, saved), inputs)
		assert.Empty(t, got, "pairs of a resumed scan that was complete")
	})
}

// hostSprayRuns runs a host-spray run of recording templates, one per id, on
// engine and returns the template and input pairs that it ran.
func hostSprayRuns(engine *Engine, inputs []string, ids ...string) []string {
	var (
		runsMu sync.Mutex
		runs   []string
	)

	tpls := make([]*templates.Template, 0, len(ids))

	for _, id := range ids {
		//nolint:exhaustruct,exhaustruct_v5 // zero values are the defaults
		tpls = append(tpls, &templates.Template{
			ID: id, Path: id, TotalRequests: 1, Executer: &recordingExecuter{path: id, mu: &runsMu, runs: &runs},
		})
	}

	engine.ExecuteScanWithOpts(context.Background(), tpls, targetsOf(inputs...), true)

	return runs
}

// pairsOf returns the pairs of every template id on every input.
func pairsOf(inputs []string, ids ...string) []string {
	pairs := make([]string, 0, len(ids)*len(inputs))

	for _, id := range ids {
		for _, input := range inputs {
			pairs = append(pairs, id+"@"+input)
		}
	}

	return pairs
}

// An engine runs host-spray once per ExecuteScanWithOpts call, as -auto-tech
// does, and the engines of -as share one resume config. The progress of one
// run can't stand for the others, so a scan interrupted after another run
// resumes from the first target.
//
//nolint:paralleltest // each scan resets the shared HTTP responses of the process
func TestHostSprayResumeAcrossRuns(t *testing.T) {
	inputs := []string{"a", "b", "c"}

	t.Run("a later run is interrupted", func(t *testing.T) {
		cfg := types.NewResumeCfg()
		engine, _ := newTaskEngine(scanstrategy.HostSpray, nil, nil, cfg)
		hostSprayRuns(engine, inputs, "fp")

		release, done := startHostSprayHeldOnB(t.Context(), t, engine, inputs)
		saved := cfg.Clone()

		release()
		<-done

		resumed, _ := newTaskEngine(scanstrategy.HostSpray, nil, nil, resumeFromSaved(t, saved))
		got := append(hostSprayRuns(resumed, inputs, "fp"), hostSprayRuns(resumed, inputs, "t1", "t2")...)
		assert.ElementsMatch(t, pairsOf(inputs, "fp", "t1", "t2"), got, "pairs of the resumed scan")
	})

	t.Run("two runs end around an interrupted one", func(t *testing.T) {
		cfg := types.NewResumeCfg()
		engine, _ := newTaskEngine(scanstrategy.HostSpray, nil, nil, cfg)
		hostSprayRuns(engine, inputs, "fp")

		release, done := startHostSprayHeldOnB(t.Context(), t, engine, inputs)
		hostSprayRuns(engine, inputs, "gp")

		saved := cfg.Clone()

		release()
		<-done

		// the runs may come in another order than in the interrupted scan
		resumed, _ := newTaskEngine(scanstrategy.HostSpray, nil, nil, resumeFromSaved(t, saved))
		got := append(hostSprayRuns(resumed, inputs, "t1", "t2"), hostSprayRuns(resumed, inputs, "fp")...)
		got = append(got, hostSprayRuns(resumed, inputs, "gp")...)
		assert.ElementsMatch(t, pairsOf(inputs, "fp", "gp", "t1", "t2"), got, "pairs of the resumed scan")
	})
}

// A later host-spray run resets the entry in both maps. A resumed scan that
// kept the entry it loaded would save it again, and a loaded completed entry
// would stay completed in every file that scan saves.
func TestHostSprayResumeInfoOfLaterRun(t *testing.T) {
	t.Parallel()

	cfg := types.NewResumeCfg()
	//nolint:exhaustruct,exhaustruct_v5 // zero values are the defaults
	cfg.ResumeFrom[hostSprayResumeID] = &types.ResumeInfo{Completed: true}
	engine, _ := newTaskEngine(scanstrategy.HostSpray, nil, nil, cfg)

	first, firstLoaded := engine.hostSprayResumeInfo()
	first.InFlight[1] = struct{}{}

	later, laterLoaded := engine.hostSprayResumeInfo()

	for name, info := range map[string]*types.ResumeInfo{
		"current":       cfg.Current[hostSprayResumeID],
		"loaded":        cfg.ResumeFrom[hostSprayResumeID],
		"later current": later,
		"later loaded":  laterLoaded,
	} {
		assert.False(t, info.Completed, "%s completed", name)
		assert.Empty(t, info.InFlight, "%s positions in flight", name)
	}

	assert.NotSame(t, later, cfg.Current[hostSprayResumeID], "the later run's progress is not saved")
	assert.True(t, firstLoaded.Completed, "the first run keeps the progress it loaded")
	assert.Equal(t, []uint32{1}, slices.Sorted(maps.Keys(first.InFlight)), "the first run keeps its positions")
}
