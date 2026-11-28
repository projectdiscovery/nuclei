package core //nolint:testpackage // it builds engines through the unexported newTaskEngine

//nolint:depguard // No depguard rules are configured, so its default list allows only the standard library.
import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	tmpltypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types/scanstrategy"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
)

// A concurrency below 1 must run with one worker, not leave a nil pool for
// the scan to dereference.
//
//nolint:paralleltest,exhaustruct,exhaustruct_v5 // engines share the default logger; fixtures keep zero values
func TestScanRunsWithConcurrencyBelowOne(t *testing.T) {
	tests := []struct {
		name     string
		workflow bool
		values   func(value int) (bulk, headlessBulk, threads, headlessThreads int)
	}{
		{"-c", false, func(v int) (int, int, int, int) { return 2, 1, v, 1 }},
		{"-c with a workflow", true, func(v int) (int, int, int, int) { return 2, 1, v, 1 }},
		{"-headc", false, func(v int) (int, int, int, int) { return 2, 1, 2, v }},
		{"-bs and -hbs", false, func(v int) (int, int, int, int) { return v, v, 2, 1 }},
		// -bs plus the default -hbs of 10 is below 1 while -bs is not.
		{"-bs with -hbs 10", false, func(v int) (int, int, int, int) { return v - 10, 10, 2, 1 }},
	}

	for _, strategy := range []scanstrategy.ScanStrategy{scanstrategy.TemplateSpray, scanstrategy.HostSpray} {
		for _, test := range tests {
			for _, value := range []int{0, -1} {
				t.Run(fmt.Sprintf("%s/%s=%d", strategy, test.name, value), func(t *testing.T) {
					engine, _ := newTaskEngine(strategy, nil, nil, nil)
					bulk, headlessBulk, threads, headlessThreads := test.values(value)
					engine.options.BulkSize = bulk
					engine.options.HeadlessBulkSize = headlessBulk
					engine.options.TemplateThreads = threads
					engine.options.HeadlessTemplateThreads = headlessThreads
					engine.workPool = engine.GetWorkPool()

					var (
						runsMu sync.Mutex
						runs   []string
					)

					templatesList := scanTemplates(test.workflow, engine.options, &runsMu, &runs)

					// A workflow clones its input, which needs the input's mutex.
					targets := &fakeTargetProvider{}

					for _, input := range []string{"a", "b"} {
						target := contextargs.NewMetaInput()
						target.Input = input
						targets.values = append(targets.values, target)
					}

					ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
					defer cancel()

					require.NotPanics(t, func() {
						engine.ExecuteScanWithOpts(ctx, templatesList, targets, true)
					})
					require.Len(t, runs, 4, "every template, or the workflow and its subtemplate, runs on every target")
				})
			}
		}
	}
}

// NewWorkPool builds every pool even when the configured size is below 1, and
// refreshing it with the same size leaves the pools usable.
//
//nolint:paralleltest // keeps the file's tests together
func TestNewWorkPoolClampsSizeToOne(t *testing.T) {
	for _, size := range []int{0, -1} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			config := WorkPoolConfig{
				InputConcurrency:         size,
				TypeConcurrency:          size,
				HeadlessInputConcurrency: size,
				HeadlessTypeConcurrency:  size,
			}
			pool := NewWorkPool(config)
			require.NotNil(t, pool.Default)
			require.NotNil(t, pool.Headless)
			require.Equal(t, 1, pool.Default.Size)
			require.Equal(t, 1, pool.Headless.Size)
			require.Equal(t, 1, pool.InputPool(tmpltypes.HTTPProtocol).Size)
			require.Equal(t, 1, pool.InputPool(tmpltypes.HeadlessProtocol).Size)

			pool.RefreshWithConfig(config)
			require.Equal(t, 1, pool.Default.Size)
			require.Equal(t, 1, pool.Headless.Size)
			pool.Wait()
		})
	}
}

// workflowTemplate returns a workflow of one step and one subtemplate. The
// step matches, so the subtemplate runs.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func workflowTemplate(options *types.Options, runsMu *sync.Mutex, runs *[]string) *templates.Template {
	progressBar, _ := progress.NewStatsTicker(0, false, false, false, 0)
	step := func(name string, outputs ...*output.InternalWrappedEvent) *workflows.WorkflowTemplate {
		return &workflows.WorkflowTemplate{Executers: []*workflows.ProtocolExecuterPair{{
			Executer: &mockExecuter{
				result: true,
				executeHook: func(input *contextargs.MetaInput) {
					runsMu.Lock()
					defer runsMu.Unlock()

					*runs = append(*runs, name+"@"+input.Input)
				},
				outputs: outputs,
			},
			Options: &protocols.ExecutorOptions{Progress: progressBar},
		}}}
	}

	matched := &output.InternalWrappedEvent{OperatorsResult: &operators.Result{}, Results: []*output.ResultEvent{{}}}
	root := step("root", matched)
	root.Subtemplates = []*workflows.WorkflowTemplate{step("sub")}

	workflow := &workflows.Workflow{
		Options:   &protocols.ExecutorOptions{Options: options},
		Workflows: []*workflows.WorkflowTemplate{root},
	}

	return &templates.Template{
		ID:               "workflow.yaml",
		Path:             "workflow.yaml",
		TotalRequests:    1,
		Workflow:         *workflow,
		CompiledWorkflow: workflow,
	}
}

// scanTemplates returns two templates, or one workflow that runs a step and a
// subtemplate.
//
//nolint:exhaustruct,exhaustruct_v5 // fixtures keep zero-value defaults
func scanTemplates(workflow bool, options *types.Options, runsMu *sync.Mutex, runs *[]string) []*templates.Template {
	if workflow {
		return []*templates.Template{workflowTemplate(options, runsMu, runs)}
	}

	list := make([]*templates.Template, 0, 2)
	for _, path := range []string{"one.yaml", "two.yaml"} {
		list = append(list, &templates.Template{
			ID:            path,
			Path:          path,
			TotalRequests: 1,
			Executer:      &recordingExecuter{path: path, mu: runsMu, runs: runs},
		})
	}

	return list
}
