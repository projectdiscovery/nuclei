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
