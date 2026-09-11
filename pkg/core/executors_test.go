package core

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	inputtypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// fakeExecuter is a simple stub for protocols.Executer used to test executeTemplateOnInput
type fakeExecuter struct {
	withResults bool
}

func (f *fakeExecuter) Compile() error                              { return nil }
func (f *fakeExecuter) Requests() int                               { return 1 }
func (f *fakeExecuter) Execute(ctx *scan.ScanContext) (bool, error) { return !f.withResults, nil }
func (f *fakeExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	if !f.withResults {
		return nil, nil
	}
	return []*output.ResultEvent{{Host: "h"}}, nil
}

// newTestEngine creates a minimal Engine for tests
func newTestEngine() *Engine {
	return New(&types.Options{})
}

func Test_executeTemplateOnInput_CallbackPath(t *testing.T) {
	e := newTestEngine()
	called := 0
	e.Callback = func(*output.ResultEvent) { called++ }

	tpl := &templates.Template{}
	tpl.Executer = &fakeExecuter{withResults: true}

	ok, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected match true")
	}
	if called == 0 {
		t.Fatalf("expected callback to be called")
	}
}

func Test_executeTemplateOnInput_ExecutePath(t *testing.T) {
	e := newTestEngine()
	tpl := &templates.Template{}
	tpl.Executer = &fakeExecuter{withResults: false}

	ok, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "x"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !ok {
		t.Fatalf("expected match true from Execute path")
	}
}

type fakeExecuterErr struct{}

func (f *fakeExecuterErr) Compile() error                              { return nil }
func (f *fakeExecuterErr) Requests() int                               { return 1 }
func (f *fakeExecuterErr) Execute(ctx *scan.ScanContext) (bool, error) { return false, nil }
func (f *fakeExecuterErr) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, fmt.Errorf("boom")
}

func Test_executeTemplateOnInput_CallbackErrorPropagates(t *testing.T) {
	e := newTestEngine()
	e.Callback = func(*output.ResultEvent) {}
	tpl := &templates.Template{}
	tpl.Executer = &fakeExecuterErr{}

	ok, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "x"})
	if err == nil {
		t.Fatalf("expected error to propagate")
	}
	if ok {
		t.Fatalf("expected match to be false on error")
	}
}

func TestExecuteTemplateOnInputReportsLifecycle(t *testing.T) {
	e := newTestEngine()
	var events []TemplateExecutionEvent
	e.SetTemplateExecutionCallback(func(event TemplateExecutionEvent) {
		events = append(events, event)
	})

	tpl := &templates.Template{ID: "template-id", Path: "http/example.yaml"}
	tpl.Executer = &fakeExecuter{withResults: false}

	_, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "https://example.com"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []TemplateExecutionEvent{
		{TemplateID: "template-id", TemplatePath: "http/example.yaml", Target: "https://example.com", State: TemplateExecutionStarted},
		{TemplateID: "template-id", TemplatePath: "http/example.yaml", Target: "https://example.com", State: TemplateExecutionFinished},
	}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("unexpected lifecycle events: got %#v want %#v", events, want)
	}
}

func TestExecuteTemplateOnInputReportsCancellationOnFinish(t *testing.T) {
	e := newTestEngine()
	var finished TemplateExecutionEvent
	e.SetTemplateExecutionCallback(func(event TemplateExecutionEvent) {
		if event.State == TemplateExecutionFinished {
			finished = event
		}
	})
	tpl := &templates.Template{ID: "interrupted"}
	tpl.Executer = &fakeExecuter{withResults: false}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = e.executeTemplateOnInput(ctx, tpl, &contextargs.MetaInput{Input: "target"})
	if finished.ContextErr != context.Canceled {
		t.Fatalf("got finish context error %v, want context canceled", finished.ContextErr)
	}
}

type fakeTargetProvider struct {
	values []*contextargs.MetaInput
}

func (f *fakeTargetProvider) Count() int64 { return int64(len(f.values)) }
func (f *fakeTargetProvider) Iterate(cb func(value *contextargs.MetaInput) bool) {
	for _, v := range f.values {
		if !cb(v) {
			return
		}
	}
}
func (f *fakeTargetProvider) Set(string, string) {}
func (f *fakeTargetProvider) SetWithProbe(string, string, inputtypes.InputLivenessProbe) error {
	return nil
}
func (f *fakeTargetProvider) SetWithExclusions(string, string) error { return nil }
func (f *fakeTargetProvider) InputType() string                      { return "test" }
func (f *fakeTargetProvider) Close()                                 {}

type slowExecuter struct{}

func (s *slowExecuter) Compile() error { return nil }
func (s *slowExecuter) Requests() int  { return 1 }
func (s *slowExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	select {
	case <-ctx.Context().Done():
		return false, ctx.Context().Err()
	case <-time.After(200 * time.Millisecond):
		return true, nil
	}
}

type adaptiveConcurrencyExecuter struct {
	delay       time.Duration
	started     atomic.Int32
	completed   atomic.Int32
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
	onStart     func(int32)
}

func (s *adaptiveConcurrencyExecuter) Compile() error { return nil }
func (s *adaptiveConcurrencyExecuter) Requests() int  { return 1 }
func (s *adaptiveConcurrencyExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	started := s.started.Add(1)
	if s.onStart != nil {
		s.onStart(started)
	}
	inFlight := s.inFlight.Add(1)
	for {
		maximum := s.maxInFlight.Load()
		if inFlight <= maximum || s.maxInFlight.CompareAndSwap(maximum, inFlight) {
			break
		}
	}
	defer s.inFlight.Add(-1)

	select {
	case <-ctx.Context().Done():
		return false, ctx.Context().Err()
	case <-time.After(s.delay):
		s.completed.Add(1)
		return true, nil
	}
}
func (s *adaptiveConcurrencyExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func TestExecuteTemplateSprayRefreshesDynamicTemplateConcurrency(t *testing.T) {
	const (
		templateCount      = 8
		initialConcurrency = 2
		finalConcurrency   = 8
	)

	var currentConcurrency atomic.Int32
	currentConcurrency.Store(initialConcurrency)
	var expandOnce sync.Once
	executer := &adaptiveConcurrencyExecuter{
		delay: 100 * time.Millisecond,
		onStart: func(started int32) {
			if started == initialConcurrency {
				expandOnce.Do(func() { currentConcurrency.Store(finalConcurrency) })
			}
		},
	}
	options := &types.Options{
		BulkSize:                1,
		TemplateThreads:         initialConcurrency,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
	}
	options.SetTemplateThreadsProvider(func() int { return int(currentConcurrency.Load()) })
	if got := options.Copy().CurrentTemplateThreads(); got != initialConcurrency {
		t.Fatalf("copied options returned concurrency %d, expected %d", got, initialConcurrency)
	}
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.NetworkProtocol,
	})
	templatesList := make([]*templates.Template, 0, templateCount)
	for range templateCount {
		templatesList = append(templatesList, &templates.Template{Executer: executer})
	}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "slow-target"}}}

	started := time.Now()
	engine.ExecuteScanWithOpts(context.Background(), templatesList, targets, true)
	elapsed := time.Since(started)

	if got := executer.completed.Load(); got != templateCount {
		t.Fatalf("completed %d templates, expected %d", got, templateCount)
	}
	if got := executer.maxInFlight.Load(); got <= initialConcurrency {
		t.Fatalf("maximum concurrency stayed at %d; expected it to expand beyond %d", got, initialConcurrency)
	}
	if elapsed >= 350*time.Millisecond {
		t.Fatalf("dynamic execution took %s; fixed concurrency would take about 400ms", elapsed)
	}
	t.Logf("dynamic execution completed all %d templates in %s with peak concurrency %d", templateCount, elapsed, executer.maxInFlight.Load())
}

func TestExecuteTemplateSprayHonorsSharedConcurrencyLimiter(t *testing.T) {
	const (
		templateCount = 8
		sharedBudget  = 2
	)

	tokens := make(chan struct{}, sharedBudget)
	executer := &adaptiveConcurrencyExecuter{delay: 50 * time.Millisecond}
	options := &types.Options{
		BulkSize:                1,
		TemplateThreads:         templateCount,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
	}
	options.SetTemplateThreadsLimiter(func(ctx context.Context) error {
		select {
		case tokens <- struct{}{}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}, func() {
		<-tokens
	})
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.NetworkProtocol,
	})
	templatesList := make([]*templates.Template, 0, templateCount)
	for range templateCount {
		templatesList = append(templatesList, &templates.Template{Executer: executer})
	}

	engine.ExecuteScanWithOpts(context.Background(), templatesList,
		&fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "slow-target"}}}, true)

	if got := executer.completed.Load(); got != templateCount {
		t.Fatalf("completed %d templates, expected %d", got, templateCount)
	}
	if got := executer.maxInFlight.Load(); got > sharedBudget {
		t.Fatalf("maximum concurrency was %d, shared budget is %d", got, sharedBudget)
	}
}
func (s *slowExecuter) ExecuteWithResults(ctx *scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func Test_executeTemplateWithTargets_RespectsCancellation(t *testing.T) {
	e := newTestEngine()
	e.SetExecuterOptions(&protocols.ExecutorOptions{Logger: e.Logger, ResumeCfg: types.NewResumeCfg(), ProtocolType: tmpltypes.HTTPProtocol})

	tpl := &templates.Template{}
	tpl.Executer = &slowExecuter{}

	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "a"}, {Input: "b"}, {Input: "c"}}}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	var matched atomic.Bool
	e.executeTemplateWithTargets(ctx, tpl, targets, &matched)
}
