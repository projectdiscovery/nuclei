package core

import (
	"context"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestPlanEntryCostWeightsByProtocol(t *testing.T) {
	headless := &templates.Template{ID: "h", RequestsHeadless: []*headless.Request{{}}, TotalRequests: 2}
	require.Equal(t, 120, planEntry(headless, &contextargs.MetaInput{Input: "t"}, nil).Cost)

	plain := &templates.Template{ID: "p", TotalRequests: 2}
	require.Equal(t, 2, planEntry(plain, &contextargs.MetaInput{Input: "t"}, nil).Cost, "unlisted protocols cost one request each")
}

// countedRequest is a request block with a fixed protocol and count.
type countedRequest struct {
	protocols.Request
	protocol tmpltypes.ProtocolType
	requests int
}

func (r countedRequest) Type() tmpltypes.ProtocolType { return r.protocol }
func (r countedRequest) Requests() int                { return r.requests }

func TestPlanEntryWeightsEachProtocolBlock(t *testing.T) {
	// one http request and ten javascript calls: Type() reports http for the
	// whole template, which would price it as 11
	mixed := &templates.Template{
		ID:            "mixed",
		RequestsHTTP:  []*http.Request{{}},
		TotalRequests: 11,
		RequestsQueue: []protocols.Request{
			countedRequest{protocol: tmpltypes.HTTPProtocol, requests: 1},
			countedRequest{protocol: tmpltypes.JavascriptProtocol, requests: 10},
		},
	}
	entry := planEntry(mixed, &contextargs.MetaInput{Input: "t"}, nil)
	require.Equal(t, 11, entry.Requests)
	require.Equal(t, 101, entry.Cost)
}

func TestPlanListsThePairsTheScanRuns(t *testing.T) {
	options := &types.Options{BulkSize: 2, TemplateThreads: 2, HeadlessBulkSize: 1, HeadlessTemplateThreads: 1}
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
		Progress:     &progressRecorder{},
		TargetScope: scopeByInput{
			"php":  {paths: []string{"thinkphp.yaml"}},
			"none": {},
		},
	})

	var (
		mu   sync.Mutex
		runs []string
	)
	var templatesList []*templates.Template
	for _, path := range []string{"thinkphp.yaml", "generic.yaml"} {
		templatesList = append(templatesList, &templates.Template{
			ID:            path,
			Path:          path,
			TotalRequests: 3,
			Executer:      &recordingExecuter{path: path, mu: &mu, runs: &runs},
		})
	}
	selfContained := &templates.Template{ID: "self.yaml", Path: "self.yaml", SelfContained: true, TotalRequests: 1}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "php"}, {Input: "none"}, {Input: "plain"}}}

	var plan []PlanEntry
	engine.Plan(append(templatesList, selfContained), targets, true, func(entry PlanEntry) { plan = append(plan, entry) })

	require.Empty(t, plan[0].Target, "a self-contained template runs once, with no target")
	require.Equal(t, []string{"self.yaml"}, plan[0].Templates)
	var planned []string
	ids := make(map[string]struct{})
	for _, entry := range plan[1:] {
		require.Equal(t, 3, entry.Requests)
		planned = append(planned, entry.Templates[0]+"@"+entry.Target)
		ids[entry.ID] = struct{}{}
	}
	require.Len(t, ids, len(plan)-1, "every entry has its own id")

	var again []PlanEntry
	engine.Plan(append(templatesList, selfContained), targets, true, func(entry PlanEntry) { again = append(again, entry) })
	require.Equal(t, plan, again, "planning the same scan again yields the same entries and ids")

	engine.ExecuteScanWithOpts(context.Background(), templatesList, targets, true)
	require.ElementsMatch(t, runs, planned, "the plan lists exactly the pairs the scan runs")
	require.ElementsMatch(t, []string{"thinkphp.yaml@php", "thinkphp.yaml@plain", "generic.yaml@plain"}, planned)
}

func TestPlanListsOriginAlternatives(t *testing.T) {
	options := &types.Options{BulkSize: 1, TemplateThreads: 1, HeadlessBulkSize: 1, HeadlessTemplateThreads: 1}
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
		Progress:     &progressRecorder{},
	})

	root := &templates.Template{
		ID:            "root.yaml",
		RequestsHTTP:  []*http.Request{{Path: []string{"{{RootURL}}/health"}}},
		TotalRequests: 1,
	}
	require.True(t, root.IsOriginScoped())
	generic := &templates.Template{ID: "generic.yaml", TotalRequests: 1}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{
		{Input: "https://example.com/a"},
		{Input: "https://example.com/b"},
		{Input: "https://other.example/a"},
		{Input: "https://example.com/a", CustomIP: "203.0.113.5"},
	}}

	var plan []PlanEntry
	engine.Plan([]*templates.Template{generic, root}, targets, true, func(entry PlanEntry) {
		plan = append(plan, entry)
	})

	var roots []PlanEntry
	for _, entry := range plan {
		if entry.Templates[0] == "root.yaml" {
			roots = append(roots, entry)
		}
	}
	require.Equal(t, []PlanEntry{
		{ID: roots[0].ID, Target: "https://example.com/a", Templates: []string{"root.yaml"}, Protocol: "http", Requests: 1, Cost: 1},
		{ID: roots[1].ID, Target: "https://example.com/b", Templates: []string{"root.yaml"}, Protocol: "http", Requests: 1, Cost: 1, AlternativeTo: roots[0].ID},
		{ID: roots[2].ID, Target: "https://other.example/a", Templates: []string{"root.yaml"}, Protocol: "http", Requests: 1, Cost: 1},
		{ID: roots[3].ID, Target: "https://example.com/a", IP: "203.0.113.5", Templates: []string{"root.yaml"}, Protocol: "http", Requests: 1, Cost: 1},
	}, roots)
	require.NotEqual(t, roots[0].ID, roots[3].ID, "a pinned address is its own attempt")

	var again []PlanEntry
	engine.Plan([]*templates.Template{generic, root}, targets, true, func(entry PlanEntry) {
		again = append(again, entry)
	})
	require.Equal(t, plan, again)
}

// fixedPlanRun is a plan run over fixed ids that records the finished ones.
type fixedPlanRun struct {
	mu       sync.Mutex
	allowed  map[string]bool
	finished []string
}

func (a *fixedPlanRun) Skip(id string) bool { return !a.allowed[id] }

func (a *fixedPlanRun) Finished(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.finished = append(a.finished, id)
}

func TestPlanRunRunsOnlyThePlannedPairs(t *testing.T) {
	options := &types.Options{BulkSize: 2, TemplateThreads: 2, HeadlessBulkSize: 1, HeadlessTemplateThreads: 1}
	engine := New(options)
	engine.SetExecuterOptions(&protocols.ExecutorOptions{
		Logger:       engine.Logger,
		Options:      options,
		ResumeCfg:    types.NewResumeCfg(),
		ProtocolType: tmpltypes.HTTPProtocol,
		Progress:     &progressRecorder{},
		TargetScope:  scopeByInput{"php": {paths: []string{"thinkphp.yaml"}}},
	})

	var (
		mu   sync.Mutex
		runs []string
	)
	var templatesList []*templates.Template
	for _, path := range []string{"thinkphp.yaml", "generic.yaml"} {
		templatesList = append(templatesList, &templates.Template{
			ID:            path,
			Path:          path,
			TotalRequests: 1,
			Executer:      &recordingExecuter{path: path, mu: &mu, runs: &runs},
		})
	}
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{{Input: "php"}, {Input: "plain"}}}

	var plan []PlanEntry
	engine.Plan(templatesList, targets, true, func(entry PlanEntry) { plan = append(plan, entry) })
	require.Len(t, plan, 3)

	// the first entry is left out of the plan, as if an agent removed it
	run := &fixedPlanRun{allowed: map[string]bool{plan[1].ID: true, plan[2].ID: true}}
	engine.SetPlanRun(run)
	engine.ExecuteScanWithOpts(context.Background(), templatesList, targets, true)

	var want []string
	for _, entry := range plan[1:] {
		want = append(want, entry.Templates[0]+"@"+entry.Target)
	}
	require.ElementsMatch(t, want, runs, "only the planned pairs run")
	require.ElementsMatch(t, []string{plan[1].ID, plan[2].ID}, run.finished, "the scan derives the ids the plan wrote")
}
