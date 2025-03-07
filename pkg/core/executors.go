package core

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	generalTypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// Executors are low level executors that deals with template execution on a target

// executeAllSelfContained executes all self contained templates that do not use `target`
func (e *Engine) executeAllSelfContained(ctx context.Context, alltemplates []*templates.Template, results *atomic.Bool, sg *sync.WaitGroup) {
	for _, v := range alltemplates {
		sg.Add(1)
		go func(template *templates.Template) {
			defer sg.Done()
			var err error
			var match bool
			ctx := scan.NewScanContext(ctx, contextargs.New(ctx))
			if e.Callback != nil {
				if results, err := template.Executer.ExecuteWithResults(ctx); err == nil {
					for _, result := range results {
						e.Callback(result)
					}
				}

				match = true
			} else {
				match, err = template.Executer.Execute(ctx)
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(v)
	}
}

// executeTemplateWithTargets executes a given template on x targets (with a internal targetpool(i.e concurrency))
func (e *Engine) executeTemplateWithTargets(ctx context.Context, template *templates.Template, target provider.InputProvider, results *atomic.Bool) {
	// this is target pool i.e max target to execute
	wg := e.workPool.InputPool(template.Type())

	var (
		index uint32
	)

	e.executerOpts.ResumeCfg.Lock()
	currentInfo, ok := e.executerOpts.ResumeCfg.Current[template.ID]
	if !ok {
		currentInfo = &generalTypes.ResumeInfo{}
		e.executerOpts.ResumeCfg.Current[template.ID] = currentInfo
	}
	if currentInfo.InFlight == nil {
		currentInfo.InFlight = make(map[uint32]struct{})
	}
	resumeFromInfo, ok := e.executerOpts.ResumeCfg.ResumeFrom[template.ID]
	if !ok {
		resumeFromInfo = &generalTypes.ResumeInfo{}
		e.executerOpts.ResumeCfg.ResumeFrom[template.ID] = resumeFromInfo
	}
	e.executerOpts.ResumeCfg.Unlock()

	// track progression
	cleanupInFlight := func(index uint32) {
		currentInfo.Lock()
		delete(currentInfo.InFlight, index)
		currentInfo.Unlock()
	}

	target.Iterate(func(scannedValue *contextargs.MetaInput) bool {
		select {
		case <-ctx.Done():
			return false // exit
		default:
		}

		// Best effort to track the host progression
		// skips indexes lower than the minimum in-flight at interruption time
		var skip bool
		if resumeFromInfo.Completed { // the template was completed
			gologger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Template already completed\n", template.ID, scannedValue.Input)
			skip = true
		} else if index < resumeFromInfo.SkipUnder { // index lower than the sliding window (bulk-size)
			gologger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Target already processed\n", template.ID, scannedValue.Input)
			skip = true
		} else if _, isInFlight := resumeFromInfo.InFlight[index]; isInFlight { // the target wasn't completed successfully
			gologger.Debug().Msgf("[%s] Repeating \"%s\": Resume - Target wasn't completed\n", template.ID, scannedValue.Input)
			// skip is already false, but leaving it here for clarity
			skip = false
		} else if index > resumeFromInfo.DoAbove { // index above the sliding window (bulk-size)
			// skip is already false - but leaving it here for clarity
			skip = false
		}

		currentInfo.Lock()
		currentInfo.InFlight[index] = struct{}{}
		currentInfo.Unlock()

		// Skip if the host has had errors
		if e.executerOpts.HostErrorsCache != nil && e.executerOpts.HostErrorsCache.Check(e.executerOpts.ProtocolType.String(), contextargs.NewWithMetaInput(ctx, scannedValue)) {
			return true
		}

		wg.Add()
		go func(index uint32, skip bool, value *contextargs.MetaInput) {
			defer wg.Done()
			defer cleanupInFlight(index)
			if skip {
				return
			}

			var match bool
			var err error
			ctxArgs := contextargs.New(ctx)
			ctxArgs.MetaInput = value
			ctx := scan.NewScanContext(ctx, ctxArgs)
			switch template.Type() {
			case types.WorkflowProtocol:
				match = e.executeWorkflow(ctx, template.CompiledWorkflow)
			default:
				if e.Callback != nil {
					if results, err := template.Executer.ExecuteWithResults(ctx); err == nil {
						for _, result := range results {
							e.Callback(result)
						}
					}
					match = true
				} else {
					match, err = template.Executer.Execute(ctx)
				}
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(index, skip, scannedValue)
		index++
		return true
	})
	wg.Wait()

	// on completion marks the template as completed
	currentInfo.Lock()
	currentInfo.Completed = true
	currentInfo.Unlock()
}

// executeTemplatesOnTarget execute given templates on given single target
func (e *Engine) executeTemplatesOnTarget(ctx context.Context, alltemplates []*templates.Template, target *contextargs.MetaInput, results *atomic.Bool) {
	// all templates are executed on single target

	// wp is workpool that contains different waitgroups for
	// headless and non-headless templates
	// global waitgroup should not be used here
	wp := e.GetWorkPool()
	defer wp.Wait()

	for _, tpl := range alltemplates {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// resize check point - nop if there are no changes
		wp.RefreshWithConfig(e.GetWorkPoolConfig())

		var sg *syncutil.AdaptiveWaitGroup
		if tpl.Type() == types.HeadlessProtocol {
			sg = wp.Headless
		} else {
			sg = wp.Default
		}
		sg.Add()
		go func(template *templates.Template, value *contextargs.MetaInput, wg *syncutil.AdaptiveWaitGroup) {
			defer wg.Done()

			var match bool
			var err error
			ctxArgs := contextargs.New(ctx)
			ctxArgs.MetaInput = value
			ctx := scan.NewScanContext(ctx, ctxArgs)
			switch template.Type() {
			case types.WorkflowProtocol:
				match = e.executeWorkflow(ctx, template.CompiledWorkflow)
			default:
				if e.Callback != nil {
					if results, err := template.Executer.ExecuteWithResults(ctx); err == nil {
						for _, result := range results {
							e.Callback(result)
						}
					}
					match = true
				} else {
					match, err = template.Executer.Execute(ctx)
				}
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(tpl, target, sg)
	}
}
