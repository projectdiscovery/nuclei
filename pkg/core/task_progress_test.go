package core

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"    //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/input"  //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/output" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/dns" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/network" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/internal/tests/testutils" //nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
)

// taskRecorder counts the tasks the engine schedules and completes.
type taskRecorder struct {
	progress.Progress
	total atomic.Int64
	done  atomic.Int64
}

func (r *taskRecorder) Init(int64, int, int64)       {}
func (r *taskRecorder) AddToTaskTotal(delta int64)   { r.total.Add(delta) }
func (r *taskRecorder) IncrementTasksBy(count int64) { r.done.Add(count) }

// downHosts reports the listed inputs as unresponsive.
type downHosts struct {
	hosterrorscache.CacheInterface
	inputs map[string]bool
}

func (d *downHosts) Check(_ string, ctx *contextargs.Context) bool {
	return d.inputs[ctx.MetaInput.Input]
}

// newTaskEngine returns an engine for strategy whose progress records tasks.
// down lists the unresponsive inputs, and a nil resume starts a fresh scan.
func newTaskEngine(strategy scanstrategy.ScanStrategy, scope protocols.TargetScope, down map[string]bool, resume *types.ResumeCfg) (*Engine, *taskRecorder) {
	options := &types.Options{
		BulkSize:                2,
		TemplateThreads:         2,
		HeadlessBulkSize:        1,
		HeadlessTemplateThreads: 1,
		ScanStrategy:            strategy.String(),
		Logger:                  gologger.DefaultLogger,
	}
	if resume == nil {
		resume = types.NewResumeCfg()
	}
	recorder := &taskRecorder{}
	executerOpts := &protocols.ExecutorOptions{
		Options:      options,
		ResumeCfg:    resume,
		ProtocolType: tmpltypes.HTTPProtocol,
		Progress:     recorder,
		TargetScope:  scope,
	}
	if down != nil {
		executerOpts.HostErrorsCache = &downHosts{inputs: down}
	}
	engine := New(options)
	executerOpts.Logger = engine.Logger
	engine.SetExecuterOptions(executerOpts)
	return engine, recorder
}

// targetsOf returns a target provider of inputs.
func targetsOf(inputs ...string) *fakeTargetProvider {
	targets := &fakeTargetProvider{}
	for _, input := range inputs {
		value := contextargs.NewMetaInput()
		value.Input = input
		targets.values = append(targets.values, value)
	}
	return targets
}

//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func TestExecuteScanCountsTasks(t *testing.T) {
	scope := scopeByInput{
		"php":    {paths: []string{"thinkphp.yaml"}},
		"tomcat": {paths: []string{"tomcat.yaml", "generic.yaml"}},
		"none":   {},
	}
	inputs := []string{"php", "tomcat", "none", "plain"}

	tests := []struct {
		name      string
		scope     protocols.TargetScope
		down      map[string]bool
		wantRuns  int
		wantTotal int64
		wantDone  int64
	}{
		{
			name: "every pair",
			// 3 templates on 4 targets, and the self-contained template once
			wantRuns:  13,
			wantTotal: 13,
			wantDone:  13,
		},
		{
			name:  "per-target profiles",
			scope: scope,
			// php 1, tomcat 2, none 0, plain 3, self-contained 1
			wantRuns:  7,
			wantTotal: 7,
			wantDone:  7,
		},
		{
			name: "unresponsive host",
			down: map[string]bool{"tomcat": true},
			// tomcat is skipped for all 3 templates
			wantRuns:  10,
			wantTotal: 13,
			wantDone:  13,
		},
		{
			name:  "unresponsive host with per-target profiles",
			scope: scope,
			down:  map[string]bool{"tomcat": true},
			// tomcat is skipped for its 2 templates
			wantRuns:  5,
			wantTotal: 7,
			wantDone:  7,
		},
	}

	for _, strategy := range []scanstrategy.ScanStrategy{scanstrategy.TemplateSpray, scanstrategy.HostSpray} {
		for _, test := range tests {
			t.Run(strategy.String()+"/"+test.name, func(t *testing.T) {
				engine, recorder := newTaskEngine(strategy, test.scope, test.down, nil)

				var (
					mu   sync.Mutex
					runs []string
				)
				var templatesList []*templates.Template
				for _, path := range []string{"thinkphp.yaml", "tomcat.yaml", "generic.yaml"} {
					templatesList = append(templatesList, &templates.Template{
						ID:            path,
						Path:          path,
						TotalRequests: 1,
						RequestsHTTP:  []*http.Request{{}},
						Executer:      &recordingExecuter{path: path, mu: &mu, runs: &runs},
					})
				}
				templatesList = append(templatesList, &templates.Template{
					ID:            "self.yaml",
					Path:          "self.yaml",
					TotalRequests: 1,
					SelfContained: true,
					Executer:      &recordingExecuter{path: "self.yaml", mu: &mu, runs: &runs},
				})
				engine.ExecuteScanWithOpts(context.Background(), templatesList, targetsOf(inputs...), true)

				require.Len(t, runs, test.wantRuns)
				require.Equal(t, test.wantTotal, recorder.total.Load(), "task total")
				require.Equal(t, test.wantDone, recorder.done.Load(), "done tasks")
			})
		}
	}
}

func TestExecuteScanCountsOriginScopedTasks(t *testing.T) {
	// a {{RootURL}} template runs once per origin, and the skipped repeats
	// are done tasks too
	inputs := []string{"http://a.test/x", "http://a.test/y", "http://a.test/z", "http://b.test/x"}

	for _, strategy := range []scanstrategy.ScanStrategy{scanstrategy.TemplateSpray, scanstrategy.HostSpray} {
		t.Run(strategy.String(), func(t *testing.T) {
			engine, recorder := newTaskEngine(strategy, nil, nil, nil)

			var (
				mu   sync.Mutex
				runs []string
			)
			templatesList := []*templates.Template{{
				ID:            "root.yaml",
				Path:          "root.yaml",
				TotalRequests: 1,
				RequestsHTTP:  []*http.Request{{Path: []string{"{{RootURL}}/"}}},
				Executer:      &recordingExecuter{path: "root.yaml", mu: &mu, runs: &runs},
			}}
			require.True(t, templatesList[0].IsOriginScoped())
			engine.ExecuteScanWithOpts(context.Background(), templatesList, targetsOf(inputs...), true)

			require.Len(t, runs, 2, "one run per origin")
			require.EqualValues(t, 4, recorder.total.Load(), "task total")
			require.EqualValues(t, 4, recorder.done.Load(), "done tasks")
		})
	}
}

//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func TestExecuteScanCountsResumedTasks(t *testing.T) {
	tests := []struct {
		name     string
		down     map[string]bool
		wantRuns []string
	}{
		{
			name:     "responsive hosts",
			wantRuns: []string{"todo.yaml@a", "todo.yaml@b"},
		},
		{
			// a resumed pair on an unresponsive host is counted once
			name:     "unresponsive host",
			down:     map[string]bool{"a": true},
			wantRuns: []string{"todo.yaml@b"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resumeCfg := types.NewResumeCfg()
			resumeCfg.ResumeFrom["done.yaml"] = &types.ResumeInfo{Completed: true}
			engine, recorder := newTaskEngine(scanstrategy.TemplateSpray, nil, test.down, resumeCfg)

			var (
				mu   sync.Mutex
				runs []string
			)
			var templatesList []*templates.Template
			for _, path := range []string{"done.yaml", "todo.yaml"} {
				templatesList = append(templatesList, &templates.Template{
					ID:            path,
					Path:          path,
					TotalRequests: 1,
					RequestsHTTP:  []*http.Request{{}},
					Executer:      &recordingExecuter{path: path, mu: &mu, runs: &runs},
				})
			}
			engine.ExecuteScanWithOpts(context.Background(), templatesList, targetsOf("a", "b"), true)

			require.ElementsMatch(t, test.wantRuns, runs)
			require.EqualValues(t, 4, recorder.total.Load(), "task total")
			require.EqualValues(t, 4, recorder.done.Load(), "done tasks")
		})
	}
}

// errConnectionRefused is the error of a request to a closed port.
var errConnectionRefused = errors.New("dial tcp 127.0.0.1:443: connect: connection refused")

const (
	httpTemplateID  = "http.yaml"
	mixedTemplateID = "mixed.yaml"
	dnsTemplateID   = "dns.yaml"
)

// TestUnresponsiveSchemelessTargetIsSkipped records a refused http request for
// a target without a scheme, at the address the request went to, as the http
// request path does. The http template on that target must then be skipped
// with a skip event, while a template with network requests and a dns
// template, whose requests also go elsewhere, still run (#8180).
//
//nolint:exhaustruct,exhaustruct_v5 // each case sets only the fields it needs
func TestUnresponsiveSchemelessTargetIsSkipped(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		probed     string // the URL the http probe found for the target, if any
		refusedURL string
		wantRuns   []string
	}{
		{name: "not probed", refusedURL: "https://127.0.0.1/n1", wantRuns: []string{mixedTemplateID, dnsTemplateID}},
		{
			name: "probed to http", probed: "http://127.0.0.1", refusedURL: "http://127.0.0.1/n1",
			wantRuns: []string{mixedTemplateID, dnsTemplateID},
		},
		{
			name: "probed to http, https refused", probed: "http://127.0.0.1", refusedURL: "https://127.0.0.1/n1",
			wantRuns: []string{httpTemplateID, mixedTemplateID, dnsTemplateID},
		},
	}

	for _, strategy := range []scanstrategy.ScanStrategy{scanstrategy.TemplateSpray, scanstrategy.HostSpray} {
		for _, test := range tests {
			t.Run(strategy.String()+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				runs, skipped, tasksLeft := scanSchemelessTarget(t, strategy, test.probed, test.refusedURL)
				require.Equal(t, test.wantRuns, runs, "templates run")

				for _, id := range runs {
					require.NotContains(t, skipped, id, "a template that ran got a skip event")
				}

				if !slices.Contains(runs, httpTemplateID) {
					require.Contains(t, skipped, httpTemplateID, "the skipped http template got no skip event")
				}

				require.Zero(t, tasksLeft, "tasks left undone")
			})
		}
	}
}

// scanSchemelessTarget scans 127.0.0.1 with an http template, an http and
// network template, and a dns template after recording a refused http request
// to refusedURL. probed is the URL the http probe found for the target, if any.
// It returns the templates that ran, the templates that got a skip event, and
// the tasks left undone.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func scanSchemelessTarget(
	t *testing.T, strategy scanstrategy.ScanStrategy, probed, refusedURL string,
) ([]string, []string, int64) {
	t.Helper()

	var (
		runs, skipped []string
		eventsMu      sync.Mutex
	)

	engine, recorder := newTaskEngine(strategy, nil, nil, nil)
	target := refuseSchemelessTarget(t, engine, probed, refusedURL)
	engine.Callback = func(event *output.ResultEvent) {
		eventsMu.Lock()
		defer eventsMu.Unlock()

		if event.Error == "host was skipped as it was found unresponsive" {
			skipped = append(skipped, event.TemplateID)
		}
	}

	// the http template comes first, so skipping it must not skip the others
	templatesList := []*templates.Template{
		{ID: httpTemplateID, RequestsHTTP: []*http.Request{{}}},
		{ID: mixedTemplateID, RequestsHTTP: []*http.Request{{}}, RequestsNetwork: []*network.Request{{}}},
		{ID: dnsTemplateID, RequestsDNS: []*dns.Request{{}}},
	}
	executers := make([]*scriptedExecuter, len(templatesList))

	for i, template := range templatesList {
		executers[i] = &scriptedExecuter{}
		template.Path, template.Executer = template.ID, executers[i]
	}

	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{target}}
	engine.ExecuteScanWithOpts(t.Context(), templatesList, targets, true)

	for i, template := range templatesList {
		if executers[i].calls > 0 {
			runs = append(runs, template.ID)
		}
	}

	return runs, skipped, recorder.total.Load() - recorder.done.Load()
}

// refuseSchemelessTarget gives engine a host errors cache and an http probe
// result, if probed is set, and returns the target 127.0.0.1 after recording a
// refused http request to refusedURL as the http request path does.
func refuseSchemelessTarget(t *testing.T, engine *Engine, probed, refusedURL string) *contextargs.MetaInput {
	t.Helper()

	cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
	t.Cleanup(cache.Close)

	engine.executerOpts.HostErrorsCache = cache
	target := contextargs.NewMetaInput()
	target.Input = "127.0.0.1"

	probes, err := hybrid.New(hybrid.DefaultMemoryOptions)
	require.NoError(t, err)
	t.Cleanup(func() { _ = probes.Close() })

	if probed != "" {
		require.NoError(t, probes.Set(target.Input, []byte(probed)))
	}

	engine.executerOpts.InputHelper = &input.Helper{InputsHTTP: probes}

	protoType := tmpltypes.HTTPProtocol.String()
	refused := contextargs.GetCopyIfAddressOutdated(contextargs.NewWithMetaInput(t.Context(), target), refusedURL)
	cache.MarkFailedOrRemove(protoType, refused, errConnectionRefused)
	require.True(t, cache.Check(protoType, refused), "the refused address must be unresponsive")

	return target
}

const (
	otherPortTemplateID = "b-live.yaml"
	firstHTTPID         = "a1.yaml"
	secondHTTPID        = "a2.yaml"
	networkTemplateID   = "tcp.yaml"
)

// TestUnresponsiveTargetKeepsTemplatesSendingElsewhere refuses the target's
// address, then scans it with an http template that sends to the target, one
// that sends to another port, another that sends to the target, and a dns
// template. The templates that send to the target are skipped. The one that
// sends to another port runs, so the request path can check that port (#8197),
// and in host-spray it does not end the skips of the templates after it.
//
//nolint:exhaustruct_v5 // fixtures keep zero-value defaults
func TestUnresponsiveTargetKeepsTemplatesSendingElsewhere(t *testing.T) {
	// compiling a request sets up global protocol state, so do it before the
	// subtests run in parallel; they only read the requests
	requests := []*http.Request{
		compiledHTTP(t, "{{BaseURL}}/a1"),
		compiledHTTP(t, "http://{{Host}}:18081/"),
		compiledHTTP(t, "{{BaseURL}}/a2"),
	}

	t.Parallel()

	tests := []struct {
		name     string
		target   string
		wantRuns []string
		// wantSkips lists the templates that get a skip event, which in
		// host-spray is one for a target whose own address is refused
		wantSkips map[scanstrategy.ScanStrategy][]string
	}{
		{
			name:     "target with a scheme",
			target:   "https://127.0.0.1",
			wantRuns: []string{otherPortTemplateID, dnsTemplateID},
			wantSkips: map[scanstrategy.ScanStrategy][]string{
				scanstrategy.TemplateSpray: {firstHTTPID, secondHTTPID},
				scanstrategy.HostSpray:     {firstHTTPID},
			},
		},
		{
			// the http requests go to https, where the refusal was recorded;
			// the dns template goes elsewhere and runs, as before
			name:     "target without a scheme",
			target:   "127.0.0.1",
			wantRuns: []string{otherPortTemplateID, dnsTemplateID},
			wantSkips: map[scanstrategy.ScanStrategy][]string{
				scanstrategy.TemplateSpray: {firstHTTPID, secondHTTPID},
				scanstrategy.HostSpray:     {firstHTTPID, secondHTTPID},
			},
		},
	}

	for _, strategy := range []scanstrategy.ScanStrategy{scanstrategy.TemplateSpray, scanstrategy.HostSpray} {
		for _, test := range tests {
			t.Run(strategy.String()+"/"+test.name, func(t *testing.T) {
				t.Parallel()

				templatesList := []*templates.Template{
					{ID: firstHTTPID, RequestsHTTP: requests[:1]},
					{ID: otherPortTemplateID, RequestsHTTP: requests[1:2]},
					{ID: secondHTTPID, RequestsHTTP: requests[2:]},
					{ID: dnsTemplateID, RequestsDNS: []*dns.Request{{}}},
				}

				runs, skipped, tasksLeft := scanAfterRefusal(t, strategy, test.target, templatesList)
				require.ElementsMatch(t, test.wantRuns, runs, "templates run")
				require.ElementsMatch(t, test.wantSkips[strategy], skipped, "templates that got a skip event")
				require.Zero(t, tasksLeft, "tasks left undone")
			})
		}
	}
}

// scanAfterRefusal scans target with templatesList after recording a refused
// request to https://127.0.0.1. It returns the templates that ran, the
// templates that got a skip event, and the tasks left undone.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func scanAfterRefusal(
	t *testing.T, strategy scanstrategy.ScanStrategy, target string, templatesList []*templates.Template,
) ([]string, []string, int64) {
	t.Helper()

	var (
		skipped  []string
		eventsMu sync.Mutex
	)

	engine, recorder := newTaskEngine(strategy, nil, nil, nil)
	engine.Callback = func(event *output.ResultEvent) {
		eventsMu.Lock()
		defer eventsMu.Unlock()

		if event.Error == "host was skipped as it was found unresponsive" {
			skipped = append(skipped, event.TemplateID)
		}
	}

	cache := hosterrorscache.New(1, hosterrorscache.DefaultMaxHostsCount, nil)
	t.Cleanup(cache.Close)

	engine.executerOpts.HostErrorsCache = cache
	input := contextargs.NewMetaInput()
	input.Input = target

	protoType := tmpltypes.HTTPProtocol.String()
	ctx := contextargs.NewWithMetaInput(t.Context(), input)
	refused := contextargs.GetCopyIfAddressOutdated(ctx, "https://127.0.0.1/a1")
	cache.MarkFailedOrRemove(protoType, refused, errConnectionRefused)
	require.True(t, cache.Check(protoType, refused), "the refused address must be unresponsive")

	executers := make([]*scriptedExecuter, len(templatesList))

	for i, template := range templatesList {
		executers[i] = &scriptedExecuter{}
		template.Path, template.Executer = template.ID, executers[i]
	}

	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{input}}
	engine.ExecuteScanWithOpts(t.Context(), templatesList, targets, true)

	var runs []string

	for i, template := range templatesList {
		if executers[i].calls > 0 {
			runs = append(runs, template.ID)
		}
	}

	return runs, skipped, recorder.total.Load() - recorder.done.Load()
}

// TestRefusedHTTPAddressKeepsOtherProtocolsRunning refuses the target's https
// address, then scans it with an http template, a network template, a mixed
// one, a dns template, and another http template. Only the http templates are
// skipped: the engine cannot tell which address the others dial, so they run
// and their requests check the address each one dials (#8203). In host-spray
// the first skip stands for the target, so the second http template gets no
// event of its own.
//
//nolint:exhaustruct_v5 // fixtures keep zero-value defaults
func TestRefusedHTTPAddressKeepsOtherProtocolsRunning(t *testing.T) {
	t.Parallel()

	wantSkips := map[scanstrategy.ScanStrategy][]string{
		scanstrategy.TemplateSpray: {firstHTTPID, secondHTTPID},
		scanstrategy.HostSpray:     {firstHTTPID},
	}

	for _, strategy := range []scanstrategy.ScanStrategy{scanstrategy.TemplateSpray, scanstrategy.HostSpray} {
		t.Run(strategy.String(), func(t *testing.T) {
			t.Parallel()

			templatesList := []*templates.Template{
				{ID: firstHTTPID, RequestsHTTP: []*http.Request{{}}},
				{ID: networkTemplateID, RequestsNetwork: []*network.Request{{}}},
				{ID: mixedTemplateID, RequestsHTTP: []*http.Request{{}}, RequestsNetwork: []*network.Request{{}}},
				{ID: dnsTemplateID, RequestsDNS: []*dns.Request{{}}},
				{ID: secondHTTPID, RequestsHTTP: []*http.Request{{}}},
			}

			runs, skipped, tasksLeft := scanAfterRefusal(t, strategy, "https://127.0.0.1", templatesList)
			require.ElementsMatch(t, []string{networkTemplateID, mixedTemplateID, dnsTemplateID}, runs, "templates run")
			require.ElementsMatch(t, wantSkips[strategy], skipped, "templates that got a skip event")
			require.Zero(t, tasksLeft, "tasks left undone")
		})
	}
}

// compiledHTTP returns an http request with path, compiled as a template run
// compiles it.
//
//nolint:exhaustruct,exhaustruct_v5 // only the path matters
func compiledHTTP(t *testing.T, path string) *http.Request {
	t.Helper()

	options := testutils.DefaultOptions
	testutils.Init(options)

	request := &http.Request{Path: []string{path}}
	info := &testutils.TemplateInfo{ID: path}
	require.NoError(t, request.Compile(testutils.NewMockExecuterOptions(options, info)))

	return request
}

// TestHTTPSkipKeepsResumeIndex refuses the https address of a schemeless
// target that a resumed scan has already passed, then scans the unfinished
// target after it. The skipped target must consume its index, so the
// unfinished one still runs (#8180).
func TestHTTPSkipKeepsResumeIndex(t *testing.T) {
	t.Parallel()

	const templateID = "http.yaml"

	resume := types.NewResumeCfg()
	resume.ResumeFrom[templateID] = &types.ResumeInfo{
		SkipUnder: 1,
		InFlight:  map[uint32]struct{}{1: {}},
	}
	engine, recorder := newTaskEngine(scanstrategy.TemplateSpray, nil, map[string]bool{
		"https://10.0.0.1": true,
	}, resume)
	executer := &scriptedExecuter{}
	template := &templates.Template{
		ID:           templateID,
		Path:         templateID,
		RequestsHTTP: []*http.Request{{}},
		Executer:     executer,
	}
	first := contextargs.NewMetaInput()
	first.Input = "10.0.0.1"
	second := contextargs.NewMetaInput()
	second.Input = "10.0.0.2"
	targets := &fakeTargetProvider{values: []*contextargs.MetaInput{first, second}}
	engine.ExecuteScanWithOpts(t.Context(), []*templates.Template{template}, targets, true)

	require.Equal(t, 1, executer.calls, "the unfinished target must run")
	require.Zero(t, recorder.total.Load()-recorder.done.Load(), "tasks left undone")
}
