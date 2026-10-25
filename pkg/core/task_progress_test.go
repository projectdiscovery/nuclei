package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/stretchr/testify/require"
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
		targets.values = append(targets.values, &contextargs.MetaInput{Input: input})
	}
	return targets
}

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
