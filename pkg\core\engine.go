package core

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/consensus"
	"go.uber.org/multierr"
)

// Engine is an executer for running Nuclei Templates/Workflows
// It automates the execution and target are added dynamically
// to the queue
type Engine struct {
	workPool     *WorkPool
	executerOpts protocols.ExecuterOptions
	Callback     func(*output.ResultEvent) // Executed on results
}

// GetWorkPool returns the workpool instance
func (e *Engine) GetWorkPool() *WorkPool {
	return e.workPool
}

// New returns a new Engine instance
func New(opts *protocols.ExecuterOptions) *Engine {
	cliOpts := opts.Options
	workPoolConfig := WorkPoolConfig{
		InputConcurrency:         cliOpts.BulkSize,
		TypeConcurrency:          cliOpts.TemplateThreads,
		HeadlessInputConcurrency: cliOpts.HeadlessBulkSize,
		HeadlessTypeConcurrency:  cliOpts.HeadlessTemplateThreads,
	}
	e := &Engine{
		workPool:     NewWorkPool(workPoolConfig),
		executerOpts: *opts,
	}
	return e
}

// GetExecuterOptions returns the executer options of the engine
func (e *Engine) GetExecuterOptions() *protocols.ExecuterOptions {
	return &e.executerOpts
}

// ExecuteWithOpts executes a workflow template (same as Execute)
func (e *Engine) ExecuteWithOpts(ctx context.Context, templatesList []*templates.Template, target InputProvider, opts protocols.ExecuterOptions) *atomic.Bool {
	return e.execute(ctx, templatesList, target, opts, false)
}

// Execute executes the given templates across the given targetsList
func (e *Engine) Execute(ctx context.Context, templatesList []*templates.Template, target InputProvider) *atomic.Bool {
	return e.execute(ctx, templatesList, target, e.executerOpts, false)
}

// ExecuteWithResults executes the given templates across the given templatesList and return results
func (e *Engine) ExecuteWithResults(ctx context.Context, templatesList []*templates.Template, target InputProvider, callback func(*output.ResultEvent)) *atomic.Bool {
	e.Callback = callback
	return e.execute(ctx, templatesList, target, e.executerOpts, false)
}

// ExecuteScanWithOpts executes scan with options
func (e *Engine) ExecuteScanWithOpts(ctx context.Context, templatesList []*templates.Template, target InputProvider, noCluster bool) *atomic.Bool {
	return e.execute(ctx, templatesList, target, e.executerOpts, noCluster)
}

func (e *Engine) execute(ctx context.Context, templatesList []*templates.Template, target InputProvider, opts protocols.ExecuterOptions, noCluster bool) *atomic.Bool {
	results := &atomic.Bool{}

	wp := e.workPool
	if noCluster {
		wp = e.workPool.Clone()
	}

	for _, template := range templatesList {
		templateType := template.Type()

		var wg *syncpool.Pool
		if templateType == types.HeadlessProtocol {
			wg = wp.Headless
		} else {
			wg = wp.Default
		}

		wg.WaitGroup.Add()
		go func(tpl *templates.Template) {
			defer wg.WaitGroup.Done()
			switch {
			case tpl.SelfContained:
				e.executeSelfContainedTemplateWithInput(ctx, tpl, results)
			default:
				e.executeTemplateWithTarget(ctx, tpl, target, results)
			}
		}(template)
	}
	wp.Wait()
	return results
}

// executeTemplateWithTarget executes a given template with a given target
func (e *Engine) executeTemplateWithTarget(ctx context.Context, template *templates.Template, target InputProvider, results *atomic.Bool) {
	wg := &sync.WaitGroup{}
	target.Iterate(func(value *contextargs.MetaInput) bool {
		wg.Add(1)
		go func(input *contextargs.MetaInput) {
			defer wg.Done()

			ctx := contextargs.NewContext(context.Background())
			ctx.MetaInput = input
			if err := template.Executer.ExecuteWithResults(ctx, func(event *output.ResultEvent) {
				results.CompareAndSwap(false, true)
				if e.Callback != nil {
					e.Callback(event)
				}
			}); err != nil {
				// not a fatal error
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", template.ID, err)
			}
		}(value)
		return true
	})
	wg.Wait()
}

// executeSelfContainedTemplateWithInput executes a self-contained template with input
func (e *Engine) executeSelfContainedTemplateWithInput(ctx context.Context, template *templates.Template, results *atomic.Bool) {
	ctx = contextargs.NewContext(context.Background())
	if err := template.Executer.ExecuteWithResults(ctx, func(event *output.ResultEvent) {
		results.CompareAndSwap(false, true)
		if e.Callback != nil {
			e.Callback(event)
		}
	}); err != nil {
		gologger.Warning().Msgf("[%s] Could not execute step: %s\n", template.ID, err)
	}
}
