package core

import (
	"context"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

// matchingExecuter reports a match on every target, as protocols do: through
// the scan context.
type matchingExecuter struct{}

func (matchingExecuter) Compile() error { return nil }
func (matchingExecuter) Requests() int  { return 1 }
func (matchingExecuter) Execute(ctx *scan.ScanContext) (bool, error) {
	ctx.LogEvent(&output.InternalWrappedEvent{Results: []*output.ResultEvent{{TemplateID: "nginx-detect", MatcherStatus: true}}})
	return true, nil
}
func (matchingExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return nil, nil
}

func TestResultHookSeesTheResultsOfEachTarget(t *testing.T) {
	options := &types.Options{BulkSize: 2, TemplateThreads: 2, HeadlessBulkSize: 1, HeadlessTemplateThreads: 1}
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
		Progress:     &progressRecorder{},
	})

	var (
		mu   sync.Mutex
		seen = map[string][]string{}
	)
	engine.SetResultHook(func(input *contextargs.MetaInput, results []*output.ResultEvent) {
		mu.Lock()
		defer mu.Unlock()
		for _, result := range results {
			seen[input.Input] = append(seen[input.Input], result.TemplateID)
		}
	})
	templatesList := []*templates.Template{{ID: "nginx-detect", Path: "nginx-detect.yaml", TotalRequests: 1, Executer: matchingExecuter{}}}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "a"}, {Input: "b"}}}
	engine.ExecuteScanWithOpts(context.Background(), templatesList, targets, true)

	require.Equal(t, map[string][]string{"a": {"nginx-detect"}, "b": {"nginx-detect"}}, seen)
}

func TestResultHookKeepsOriginScopedTemplatesOncePerOrigin(t *testing.T) {
	e := newTestEngine()
	exec := &scriptedExecuter{}
	tpl := originScopedTemplate("{{RootURL}}/health")
	tpl.Executer = exec
	var seen []string
	e.SetResultHook(func(input *contextargs.MetaInput, _ []*output.ResultEvent) { seen = append(seen, input.Input) })

	for _, target := range []string{"https://example.com/a", "https://example.com/b"} {
		_, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: target})
		require.NoError(t, err)
	}
	require.Equal(t, 1, exec.calls, "the hook does not repeat the origin's requests")
	require.Equal(t, []string{"https://example.com/a"}, seen)
}

func TestResultHookSeesResultsOnTheCallbackPath(t *testing.T) {
	e := newTestEngine()
	e.Callback = func(*output.ResultEvent) {}
	var seen []*output.ResultEvent
	e.SetResultHook(func(_ *contextargs.MetaInput, results []*output.ResultEvent) { seen = append(seen, results...) })
	tpl := &templates.Template{ID: "nginx-detect", Executer: resultsExecuter{}}

	_, err := e.executeTemplateOnInput(context.Background(), tpl, &contextargs.MetaInput{Input: "a"})
	require.NoError(t, err)
	require.Len(t, seen, 1)
}

type resultsExecuter struct{ matchingExecuter }

func (resultsExecuter) ExecuteWithResults(*scan.ScanContext) ([]*output.ResultEvent, error) {
	return []*output.ResultEvent{{TemplateID: "nginx-detect", MatcherStatus: true}}, nil
}
