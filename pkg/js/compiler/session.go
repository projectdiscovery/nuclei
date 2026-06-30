package compiler

import (
	"context"
	"fmt"
	"time"

	"github.com/projectdiscovery/goja"
)

// sessionState represents the various states a session can be in during its lifecycle.
type sessionState uint8

const (
	sessionRunning sessionState = iota
	sessionCompleted
	sessionFailed
	sessionAbandoned
)

type gojaRunResult struct {
	result goja.Value
	err    error
}

// sessionConfig defines the configuration for a session, including the runtime,
// program, arguments, and lifecycle hooks for preparation, cleanup, and result
// finalization. It also includes callbacks for handling resource release and
// abandonment scenarios.
type sessionConfig struct {
	ctx     context.Context
	runtime *goja.Runtime
	program *goja.Program
	args    *ExecuteArgs
	opts    *ExecuteOptions

	prepareRuntime func(*goja.Runtime) error
	cleanupRuntime func(*goja.Runtime)
	finalizeResult func(*goja.Runtime, goja.Value) (goja.Value, error)

	returnRuntime        func(*goja.Runtime)
	releaseSlot          func()
	releaseAbandonedSlot func()
	onAbandon            func(error)
}

// session encapsulates the execution of a single JavaScript program, managing
// its lifecycle, including preparation, execution, and cleanup.
type session struct {
	config sessionConfig

	resultChan chan gojaRunResult
	state      sessionState

	commonPrepared bool
	commonCleaned  bool
	pathPrepared   bool
	pathCleaned    bool
}

func newSession(config sessionConfig) *session {
	if config.args == nil {
		config.args = NewExecuteArgs()
	}
	if config.opts == nil {
		config.opts = &ExecuteOptions{}
	}
	return &session{
		config:     config,
		resultChan: make(chan gojaRunResult, 1),
	}
}

func executeWithRuntime(ctx context.Context, runtime *goja.Runtime, p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions, onOrphanExit func()) (goja.Value, error) {
	session := newSession(sessionConfig{
		ctx:                  ctx,
		runtime:              runtime,
		program:              p,
		args:                 args,
		opts:                 opts,
		releaseAbandonedSlot: onOrphanExit,
	})
	return session.run()
}

func (s *session) run() (goja.Value, error) {
	defer s.releaseAfterExit()
	defer s.cleanupPath()
	defer s.cleanupCommon()

	s.prepareCommon()
	if s.config.prepareRuntime != nil {
		s.pathPrepared = true
		if err := s.config.prepareRuntime(s.config.runtime); err != nil {
			s.state = sessionFailed
			return nil, err
		}
	}
	if s.config.opts.Callback != nil {
		if err := s.config.opts.Callback(s.config.runtime); err != nil {
			s.state = sessionFailed
			return nil, err
		}
	}

	s.start()
	result, err := s.wait()
	if err != nil {
		return nil, err
	}
	if result.err != nil {
		s.state = sessionFailed
		return nil, result.err
	}

	s.cleanupCommon()
	if s.config.finalizeResult != nil {
		value, err := s.config.finalizeResult(s.config.runtime, result.result)
		if err != nil {
			s.state = sessionFailed
			return nil, err
		}
		s.state = sessionCompleted
		return value, nil
	}

	s.state = sessionCompleted
	return result.result, nil
}

func (s *session) prepareCommon() {
	s.commonPrepared = true

	s.config.runtime.ClearInterrupt()
	_ = s.config.runtime.Set("template", s.config.args.TemplateCtx)
	for k, v := range s.config.args.Args {
		_ = s.config.runtime.Set(k, v)
	}

	s.config.runtime.SetContextValue("executionId", s.config.opts.ExecutionId)
	s.config.runtime.SetContextValue("ctx", s.config.ctx)
	enableRequire(s.config.runtime)
}

func (s *session) start() {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.resultChan <- gojaRunResult{err: fmt.Errorf("panic: %s", r)}
			}
		}()

		result, err := s.config.runtime.RunProgram(s.config.program)
		s.resultChan <- gojaRunResult{result: result, err: err}
	}()
}

func (s *session) wait() (gojaRunResult, error) {
	select {
	case <-s.config.ctx.Done():
		contextErr := s.config.ctx.Err()
		s.config.runtime.Interrupt(contextErr)

		timer := time.NewTimer(time.Second)
		defer timer.Stop()

		select {
		case result := <-s.resultChan:
			return result, nil
		case <-timer.C:
			return gojaRunResult{}, s.abandon(contextErr)
		}
	case result := <-s.resultChan:
		return result, nil
	}
}

func (s *session) abandon(contextErr error) error {
	s.state = sessionAbandoned
	err := fmt.Errorf("%w: %w", errRuntimeTerminationTimeout, contextErr)
	if s.config.releaseAbandonedSlot != nil {
		resultChan := s.resultChan
		releaseAbandonedSlot := s.config.releaseAbandonedSlot
		go func() {
			<-resultChan
			releaseAbandonedSlot()
		}()
	}
	if s.config.onAbandon != nil {
		s.config.onAbandon(err)
	}
	return err
}

func (s *session) cleanupCommon() {
	if s.state == sessionAbandoned || !s.commonPrepared || s.commonCleaned {
		return
	}
	s.commonCleaned = true

	_ = s.config.runtime.GlobalObject().Delete("template")
	for k := range s.config.args.Args {
		_ = s.config.runtime.GlobalObject().Delete(k)
	}
	if s.config.opts.Cleanup != nil {
		s.config.opts.Cleanup(s.config.runtime)
	}
	s.config.runtime.RemoveContextValue("executionId")
	s.config.runtime.RemoveContextValue("ctx")
}

func (s *session) cleanupPath() {
	if s.state == sessionAbandoned || !s.pathPrepared || s.pathCleaned {
		return
	}
	s.pathCleaned = true
	if s.config.cleanupRuntime != nil {
		s.config.cleanupRuntime(s.config.runtime)
	}
}

func (s *session) releaseAfterExit() {
	if s.state == sessionAbandoned {
		return
	}
	if s.config.returnRuntime != nil {
		s.config.returnRuntime(s.config.runtime)
	}
	if s.config.releaseSlot != nil {
		s.config.releaseSlot()
	}
}
