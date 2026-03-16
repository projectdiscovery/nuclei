package core

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/honeypotcache"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	generalTypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// Executors are low level executors that deals with template execution on a target

// executeAllSelfContained executes all self contained templates that do not use `target`
func (e *Engine) executeAllSelfContained(ctx context.Context, alltemplates []*templates.Template, results *atomic.Bool, sg *sync.WaitGroup) {
	// Self-contained templates carry their own target input and do not scan external hosts.
	// Honeypot detection is host-keyed and therefore not applicable here.
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
				e.options.Logger.Warning().Msgf("[%s] Could not execute step (self-contained): %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(v)
	}
}

// executeTemplateWithTargets executes a given template on x targets (with a internal targetpool(i.e concurrency))
func (e *Engine) executeTemplateWithTargets(ctx context.Context, template *templates.Template, target provider.InputProvider, results *atomic.Bool) {
	if e.workPool == nil {
		e.workPool = e.GetWorkPool()
	}
	// Bounded worker pool using input concurrency
	pool := e.workPool.InputPool(template.Type())
	workerCount := 1
	if pool != nil && pool.Size > 0 {
		workerCount = pool.Size
	}

	var (
		index uint32
	)

	e.executerOpts.ResumeCfg.Lock()
	currentInfo, ok := e.executerOpts.ResumeCfg.Current[template.ID]
	if !ok {
		currentInfo = &generalTypes.ResumeInfo{}
		e.executerOpts.ResumeCfg.Current[template.ID] = currentInfo
	}
	currentInfo.InitInFlight()
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

	// task represents a single target execution unit
	type task struct {
		index uint32
		skip  bool
		value *contextargs.MetaInput
	}

	tasks := make(chan task)
	var workersWg sync.WaitGroup
	workersWg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer workersWg.Done()
			for t := range tasks {
				func() {
					defer cleanupInFlight(t.index)
					select {
					case <-ctx.Done():
						return
					default:
					}
					if t.skip {
						return
					}

					match, err := e.executeTemplateOnInput(ctx, template, t.value)
					if err != nil {
						e.options.Logger.Warning().Msgf("[%s] Could not execute step on %s: %s\n", template.ID, t.value.Input, err)
					}
					results.CompareAndSwap(false, match)
				}()
			}
		}()
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
		if resumeFromInfo.IsCompleted() { // the template was completed
			e.options.Logger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Template already completed", template.ID, scannedValue.Input)
			skip = true
		} else if index < resumeFromInfo.GetSkipUnder() { // index lower than the sliding window (bulk-size)
			e.options.Logger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Target already processed", template.ID, scannedValue.Input)
			skip = true
		} else if resumeFromInfo.IsInFlight(index) { // the target wasn't completed successfully
			e.options.Logger.Debug().Msgf("[%s] Repeating \"%s\": Resume - Target wasn't completed", template.ID, scannedValue.Input)
			// skip is already false, but leaving it here for clarity
			skip = false
		} else if index > resumeFromInfo.GetDoAbove() { // index above the sliding window (bulk-size)
			// skip is already false - but leaving it here for clarity
			skip = false
		}

		currentInfo.Lock()
		currentInfo.InFlight[index] = struct{}{}
		currentInfo.Unlock()

		// Skip if the host has had errors
		if e.executerOpts.HostErrorsCache != nil && e.executerOpts.HostErrorsCache.Check(e.executerOpts.ProtocolType.String(), contextargs.NewWithMetaInput(ctx, scannedValue)) {
			skipEvent := &output.ResultEvent{
				TemplateID:    template.ID,
				TemplatePath:  template.Path,
				Info:          template.Info,
				Type:          e.executerOpts.ProtocolType.String(),
				Host:          scannedValue.Input,
				MatcherStatus: false,
				Error:         "host was skipped as it was found unresponsive",
				Timestamp:     time.Now(),
			}

			if e.Callback != nil {
				e.Callback(skipEvent)
			} else if e.executerOpts.Output != nil {
				_ = e.executerOpts.Output.Write(skipEvent)
			}
			return true
		}

		// Skip honeypot hosts.
		if e.executerOpts.HoneypotCache != nil {
			if e.executerOpts.HoneypotCache.Check(contextargs.NewWithMetaInput(ctx, scannedValue)) {
				e.options.Logger.Warning().Msgf("[honeypot] skipping %s — exceeded match density threshold", scannedValue.Input)
				skipEvent := &output.ResultEvent{
					TemplateID:    template.ID,
					TemplatePath:  template.Path,
					Info:          template.Info,
					Type:          e.executerOpts.ProtocolType.String(),
					Host:          scannedValue.Input,
					MatcherStatus: false,
					Error:         "host was skipped as it was identified as a honeypot",
					Timestamp:     time.Now(),
				}
				if e.Callback != nil {
					e.Callback(skipEvent)
				} else if e.executerOpts.Output != nil {
					_ = e.executerOpts.Output.Write(skipEvent)
				}
				return true
			}
		}

		tasks <- task{index: index, skip: skip, value: scannedValue}
		index++
		return true
	})

	close(tasks)
	workersWg.Wait()

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

		// Check whether the target has already been marked as permanently
		// unresponsive by HostErrorsCache before spawning another goroutine.
		if e.executerOpts.HostErrorsCache != nil &&
			e.executerOpts.HostErrorsCache.Check(e.executerOpts.ProtocolType.String(), contextargs.NewWithMetaInput(ctx, target)) {
			skipEvent := &output.ResultEvent{
				TemplateID:    tpl.ID,
				TemplatePath:  tpl.Path,
				Info:          tpl.Info,
				Type:          e.executerOpts.ProtocolType.String(),
				Host:          target.Input,
				MatcherStatus: false,
				Error:         "host was skipped as it was found unresponsive",
				Timestamp:     time.Now(),
			}
			if e.Callback != nil {
				e.Callback(skipEvent)
			} else if e.executerOpts.Output != nil {
				_ = e.executerOpts.Output.Write(skipEvent)
			}
			break
		}

		if e.executerOpts.HoneypotCache != nil {
			if e.executerOpts.HoneypotCache.Check(contextargs.NewWithMetaInput(ctx, target)) {
				e.options.Logger.Warning().Msgf("[honeypot] skipping %s — exceeded match density threshold", target.Input)
				skipEvent := &output.ResultEvent{
					TemplateID:    tpl.ID,
					TemplatePath:  tpl.Path,
					Info:          tpl.Info,
					Type:          e.executerOpts.ProtocolType.String(),
					Host:          target.Input,
					MatcherStatus: false,
					Error:         "host was skipped as it was identified as a honeypot",
					Timestamp:     time.Now(),
				}
				if e.Callback != nil {
					e.Callback(skipEvent)
				} else if e.executerOpts.Output != nil {
					_ = e.executerOpts.Output.Write(skipEvent)
				}
				break
			}
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

			match, err := e.executeTemplateOnInput(ctx, template, value)
			if err != nil {
				e.options.Logger.Warning().Msgf("[%s] Could not execute step on %s: %s\n", template.ID, value.Input, err)
			}
			results.CompareAndSwap(false, match)
		}(tpl, target, sg)
	}
}

// executeTemplateOnInput performs template execution for a single input and returns match status and error
func (e *Engine) executeTemplateOnInput(ctx context.Context, template *templates.Template, value *contextargs.MetaInput) (bool, error) {
	ctxArgs := contextargs.New(ctx)
	ctxArgs.MetaInput = value
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	switch template.Type() {
	case types.WorkflowProtocol:
		return e.executeWorkflow(scanCtx, template.CompiledWorkflow), nil
	default:
		// Use ExecuteWithResults when honeypot cache is active so that response
		// content is available for signature-based detection on all execution paths.
		wantsResults := e.Callback != nil ||
			(e.executerOpts != nil && e.executerOpts.HoneypotCache != nil)

		if wantsResults {
			results, err := template.Executer.ExecuteWithResults(scanCtx)
			if err != nil {
				return false, err
			}

			hasResults := len(results) > 0
			if hasResults && e.executerOpts != nil && e.executerOpts.HoneypotCache != nil {
				for _, result := range results {
					// Check response content for static honeypot signatures.
					if result.Response != "" {
						if matched, sigName := honeypotcache.CheckSignature(result.Response); matched {
							e.options.Logger.Warning().Msgf("[honeypot-sig] %s matched signature: %s", value.Input, sigName)
							// Always mark the real template ID so density tracking records it.
							e.executerOpts.HoneypotCache.MarkMatch(scanCtx.Input, template.ID)
							// Inject synthetic marks to push above the absolute threshold when set.
							if e.executerOpts.Options != nil && e.executerOpts.Options.MaxHostMatch > 0 {
								for i := 0; i < e.executerOpts.Options.MaxHostMatch; i++ {
									e.executerOpts.HoneypotCache.MarkMatch(scanCtx.Input, fmt.Sprintf("__sig_%d_%d", i, result.Timestamp.UnixNano()))
								}
							}
						}
					}
				}
				// Always mark density for this template regardless of signature.
				e.executerOpts.HoneypotCache.MarkMatch(scanCtx.Input, template.ID)

				// If the host is now flagged, suppress results — they are honeypot bait.
				if e.executerOpts.HoneypotCache.Check(scanCtx.Input) {
					return false, nil
				}
			}

			if e.Callback != nil {
				for _, result := range results {
					e.Callback(result)
				}
			} else if e.executerOpts != nil && e.executerOpts.Output != nil {
				for _, result := range results {
					_ = e.executerOpts.Output.Write(result)
				}
			}
			return hasResults, nil
		}

		hasResults, err := template.Executer.Execute(scanCtx)
		if err != nil {
			return false, err
		}
		return hasResults, nil
	}
}
