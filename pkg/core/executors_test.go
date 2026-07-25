package core

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	inputtypes "github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
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
	return New(&types.Options{
		BulkSize:                1,
		TemplateThreads:         1,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
	})
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

type fakeTargetProvider struct {
	values    []*contextargs.MetaInput
	inputType string
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
func (f *fakeTargetProvider) InputType() string {
	if f.inputType != "" {
		return f.inputType
	}
	return "test"
}
func (f *fakeTargetProvider) Close() {}

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

type countingExecuter struct {
	executions atomic.Int32
}

func (c *countingExecuter) Compile() error { return nil }
func (c *countingExecuter) Requests() int  { return 1 }
func (c *countingExecuter) Execute(*scan.ScanContext) (bool, error) {
	c.executions.Add(1)
	return false, nil
}
func (c *countingExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	c.executions.Add(1)
	return nil, nil
}

type progressSpy struct {
	totalDelta atomic.Int64
}

func (*progressSpy) Stop()                           {}
func (*progressSpy) Init(int64, int, int64)          {}
func (p *progressSpy) AddToTotal(delta int64)        { p.totalDelta.Add(delta) }
func (*progressSpy) IncrementRequests()              {}
func (*progressSpy) SetRequests(uint64)              {}
func (*progressSpy) IncrementMatched()               {}
func (*progressSpy) IncrementErrorsBy(int64)         {}
func (*progressSpy) IncrementFailedRequestsBy(int64) {}

func TestExecuteTemplateWithTargetsAppliesPerTargetFilter(t *testing.T) {
	e := newTestEngine()
	progress := &progressSpy{}
	e.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       e.Logger,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
		Progress:     progress,
	})

	executer := &countingExecuter{}
	template := filteredTestTemplate("apache.yaml", "apache", severity.High, executer)
	allowed := preparedMetaInput("https://allowed.example", []string{"apache"})
	denied := preparedMetaInput("https://denied.example", []string{"nginx"})
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{denied, allowed}}

	var matched atomic.Bool
	e.executeTemplateWithTargets(context.Background(), template, targets, &matched)

	require.EqualValues(t, 1, executer.executions.Load())
	require.EqualValues(t, -1, progress.totalDelta.Load())
}

func TestExecuteTemplatesOnTargetAppliesPerTargetFilter(t *testing.T) {
	e := newTestEngine()
	progress := &progressSpy{}
	e.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       e.Logger,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
		Progress:     progress,
	})

	allowedExecuter := &countingExecuter{}
	deniedExecuter := &countingExecuter{}
	templatesList := []*templates.Template{
		filteredTestTemplate("apache.yaml", "apache", severity.High, allowedExecuter),
		filteredTestTemplate("nginx.yaml", "nginx", severity.High, deniedExecuter),
	}
	target := preparedMetaInput("https://example.com", []string{"apache"})

	var matched atomic.Bool
	e.executeTemplatesOnTarget(context.Background(), templatesList, target, &matched)

	require.EqualValues(t, 1, allowedExecuter.executions.Load())
	require.Zero(t, deniedExecuter.executions.Load())
	require.EqualValues(t, -1, progress.totalDelta.Load())
}

func TestTemplateMatchesAnyTargetForSelfContainedTemplate(t *testing.T) {
	executer := &countingExecuter{}
	template := filteredTestTemplate("apache.yaml", "apache", severity.High, executer)
	template.SelfContained = true

	deniedOnly := &fakeTargetProvider{
		inputType: "TargetInputProvider",
		values:    []*contextargs.MetaInput{preparedMetaInput("https://denied.example", []string{"nginx"})},
	}
	require.False(t, templateMatchesAnyTarget(template, deniedOnly))

	withAllowed := &fakeTargetProvider{
		inputType: "TargetInputProvider",
		values: []*contextargs.MetaInput{
			preparedMetaInput("https://denied.example", []string{"nginx"}),
			preparedMetaInput("https://allowed.example", []string{"apache"}),
		},
	}
	require.True(t, templateMatchesAnyTarget(template, withAllowed))
}

func TestAdjustSelfContainedProgressForTargetFilters(t *testing.T) {
	e := newTestEngine()
	progress := &progressSpy{}
	e.SetExecuterOptions(&protocols.ExecutorOptions{Progress: progress})
	template := filteredTestTemplate("self-contained.yaml", "code", severity.Info, &countingExecuter{})
	targets := &fakeTargetProvider{
		inputType: "TargetInputProvider",
		values: []*contextargs.MetaInput{
			preparedMetaInput("https://one.example", []string{"code"}),
			preparedMetaInput("https://two.example", []string{"code"}),
		},
	}

	e.adjustSelfContainedProgress(template, targets, true)
	require.EqualValues(t, -1, progress.totalDelta.Load())

	progress.totalDelta.Store(0)
	e.adjustSelfContainedProgress(template, targets, false)
	require.EqualValues(t, -2, progress.totalDelta.Load())
}

func filteredTestTemplate(path, tag string, templateSeverity severity.Severity, executer protocols.Executer) *templates.Template {
	return &templates.Template{
		Path: path,
		Info: model.Info{
			Tags:           stringslice.New([]string{tag}),
			SeverityHolder: severity.Holder{Severity: templateSeverity},
		},
		Executer:      executer,
		TotalRequests: 1,
	}
}

func preparedMetaInput(input string, tags []string) *contextargs.MetaInput {
	filter := &contextargs.TargetFilter{}
	filter.Prepare(tags, nil, nil, nil, nil, false)
	return &contextargs.MetaInput{Input: input, TargetFilter: filter}
}
