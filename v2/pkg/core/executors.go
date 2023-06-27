package core

import (
	"sync"
	"sync/atomic"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	generalTypes "github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/remeh/sizedwaitgroup"
)

// Executors are low level executors that deals with template execution on a target

// executeAllSelfContained executes all self contained templates that do not use `target`
func (e *Engine) executeAllSelfContained(alltemplates []*templates.Template, results *atomic.Bool, sg *sync.WaitGroup) {
	for _, v := range alltemplates {
		sg.Add(1)
		go func(template *templates.Template) {
			defer sg.Done()
			var err error
			var match bool
			if e.Callback != nil {
				err = template.Executer.ExecuteWithResults(contextargs.New(), func(event *output.InternalWrappedEvent) {
					for _, result := range event.Results {
						e.Callback(result)
					}
				})
				match = true
			} else {
				match, err = template.Executer.Execute(contextargs.New())
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(v)
	}
}

// executeTemplateWithTarget executes a given template on x targets (with a internal targetpool(i.e concurrency))
func (e *Engine) executeTemplateWithTargets(template *templates.Template, target InputProvider, results *atomic.Bool) {
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

	target.Scan(func(scannedValue *contextargs.MetaInput) bool {
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
		if e.executerOpts.HostErrorsCache != nil && e.executerOpts.HostErrorsCache.Check(scannedValue.ID()) {
			return true
		}

		wg.WaitGroup.Add()
		go func(index uint32, skip bool, value *contextargs.MetaInput) {
			defer wg.WaitGroup.Done()
			defer cleanupInFlight(index)
			if skip {
				return
			}

			var match bool
			var err error
			switch template.Type() {
			case types.WorkflowProtocol:
				match = e.executeWorkflow(value, template.CompiledWorkflow)
			default:
				ctxArgs := contextargs.New()
				ctxArgs.MetaInput = value
				if e.Callback != nil {
					err = template.Executer.ExecuteWithResults(ctxArgs, func(event *output.InternalWrappedEvent) {
						for _, result := range event.Results {
							e.Callback(result)
						}
					})
					match = true
				} else {
					match, err = template.Executer.Execute(ctxArgs)
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
	wg.WaitGroup.Wait()

	// on completion marks the template as completed
	currentInfo.Lock()
	currentInfo.Completed = true
	currentInfo.Unlock()
}

// executeTemplatesOnTarget execute given templates on given single target
func (e *Engine) executeTemplatesOnTarget(alltemplates []*templates.Template, target *contextargs.MetaInput, results *atomic.Bool) {
	// all templates are executed on single target

	// wp is workpool that contains different waitgroups for
	// headless and non-headless templates
	// global waitgroup should not be used here
	wp := e.GetWorkPool()

	for _, tpl := range alltemplates {
		var sg *sizedwaitgroup.SizedWaitGroup
		if tpl.Type() == types.HeadlessProtocol {
			sg = wp.Headless
		} else {
			sg = wp.Default
		}
		sg.Add()
		go func(template *templates.Template, value *contextargs.MetaInput, wg *sizedwaitgroup.SizedWaitGroup) {
			defer wg.Done()

			var match bool
			var err error
			switch template.Type() {
			case types.WorkflowProtocol:
				match = e.executeWorkflow(value, template.CompiledWorkflow)
			default:
				ctxArgs := contextargs.New()
				ctxArgs.MetaInput = value
				if e.Callback != nil {
					err = template.Executer.ExecuteWithResults(ctxArgs, func(event *output.InternalWrappedEvent) {
						for _, result := range event.Results {
							e.Callback(result)
						}
					})
					match = true
				} else {
					match, err = template.Executer.Execute(ctxArgs)
				}
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(tpl, target, sg)
	}
	wp.Wait()
}

type ChildExecuter struct {
	e *Engine

	results *atomic.Bool
}

// Close closes the executer returning bool results
func (e *ChildExecuter) Close() *atomic.Bool {
	e.e.workPool.Wait()
	return e.results
}

// Execute executes a template and URLs
func (e *ChildExecuter) Execute(template *templates.Template, value *contextargs.MetaInput) {
	templateType := template.Type()

	var wg *sizedwaitgroup.SizedWaitGroup
	if templateType == types.HeadlessProtocol {
		wg = e.e.workPool.Headless
	} else {
		wg = e.e.workPool.Default
	}

	wg.Add()
	go func(tpl *templates.Template) {
		defer wg.Done()

		ctxArgs := contextargs.New()
		ctxArgs.MetaInput = value
		match, err := template.Executer.Execute(ctxArgs)
		if err != nil {
			gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.e.executerOpts.Colorizer.BrightBlue(template.ID), err)
		}
		e.results.CompareAndSwap(false, match)
	}(template)
}

// ExecuteWithOpts executes with the full options
func (e *Engine) ChildExecuter() *ChildExecuter {
	return &ChildExecuter{
		e:       e,
		results: &atomic.Bool{},
	}
}
