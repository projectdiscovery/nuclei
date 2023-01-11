package core

import (
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	generalTypes "github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/remeh/sizedwaitgroup"
	"go.uber.org/atomic"
)

/*
Executors are low level executors that deals with template execution on a target
*/

// executeAllSelfContained executes all self contained templates that do not use `target`
func (e *Engine) executeAllSelfContained(alltemplates []*templates.Template, results *atomic.Bool, sg *sync.WaitGroup) {
	for _, v := range alltemplates {
		sg.Add(1)
		go func(template *templates.Template) {
			defer sg.Done()
			match, err := template.Executer.Execute(contextargs.New())
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(v)
	}
}

// executeTemplateWithTarget executes given template on many target[s] add adds them to given workpool
func (e *Engine) executeTemplateWithManyTargets(template *templates.Template, target InputProvider, wp *sizedwaitgroup.SizedWaitGroup, results *atomic.Bool) {
	/*
		If target ==1
		wp(waitgroup) is just a placeholde
		If target > 1
		template execute is added to global concurrency pool
		wp == global worker pool
	*/
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
			gologger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Template already completed\n", template.ID, scannedValue)
			skip = true
		} else if index < resumeFromInfo.SkipUnder { // index lower than the sliding window (bulk-size)
			gologger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Target already processed\n", template.ID, scannedValue)
			skip = true
		} else if _, isInFlight := resumeFromInfo.InFlight[index]; isInFlight { // the target wasn't completed successfully
			gologger.Debug().Msgf("[%s] Repeating \"%s\": Resume - Target wasn't completed\n", template.ID, scannedValue)
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

		wp.Add()
		go func(index uint32, skip bool, value *contextargs.MetaInput) {
			defer wp.Done()
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
				match, err = template.Executer.Execute(ctxArgs)
			}
			if err != nil {
				gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(index, skip, scannedValue)

		index++
		return true
	})
	// on completion marks the template as completed
	currentInfo.Lock()
	currentInfo.Completed = true
	currentInfo.Unlock()
}

// executeTemplateWithOneTarget executes given template on given target
func (e *Engine) executeTemplateWithOneTarget(template *templates.Template, target *contextargs.MetaInput, wp *sizedwaitgroup.SizedWaitGroup, results *atomic.Bool) {
	defer wp.Done()

	var match bool
	var err error
	switch template.Type() {
	case types.WorkflowProtocol:
		match = e.executeWorkflow(target, template.CompiledWorkflow)
	default:
		ctxArgs := contextargs.New()
		ctxArgs.MetaInput = target
		match, err = template.Executer.Execute(ctxArgs)
	}
	if err != nil {
		gologger.Warning().Msgf("[%s] Could not execute step: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
	}
	results.CompareAndSwap(false, match)
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
