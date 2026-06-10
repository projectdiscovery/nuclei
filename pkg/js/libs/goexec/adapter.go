package goexec

import (
	"context"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// Runner executes a normalized Windows helper request.
type Runner interface {
	Run(ctx context.Context, req Request) (*Result, error)
}

// Request is the adapter boundary between JavaScript helpers and GoExec.
type Request struct {
	Module         string
	Method         string
	Target         string
	Auth           *Auth
	Executable     string
	Args           string
	Command        string
	TaskName       string
	ServiceName    string
	Namespace      string
	ClassName      string
	MethodName     string
	MethodArgsJSON string
	Options        ExecutionOptions
}

var (
	runnerMu      sync.RWMutex
	defaultRunner Runner = &GoExecRunner{}
)

type executionIDContextKey struct{}

var executionIDKey executionIDContextKey

// SetRunnerForTesting replaces the adapter runner and returns a restore func.
func SetRunnerForTesting(runner Runner) func() {
	runnerMu.Lock()
	previous := defaultRunner
	defaultRunner = runner
	runnerMu.Unlock()
	return func() {
		runnerMu.Lock()
		defaultRunner = previous
		runnerMu.Unlock()
	}
}

// WithExecutionID adds nuclei's execution ID to contexts passed through manual
// JavaScript closures that do not go through gojs' context injection path.
func WithExecutionID(ctx context.Context, executionID string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if executionID == "" {
		return ctx
	}
	if _, ok := ctx.Value(executionIDKey).(string); !ok {
		ctx = context.WithValue(ctx, executionIDKey, executionID)
	}
	if protocolstate.GetExecutionContext(ctx) == nil {
		ctx = protocolstate.WithExecutionID(ctx, &protocolstate.ExecutionContext{ExecutionID: executionID})
	}
	return ctx
}

// Run executes a helper request and always returns a structured Result.
func Run(ctx context.Context, req Request) *Result {
	start := time.Now()
	normalized, err := normalizeTarget(req.Target)
	if err != nil {
		result := newResult(req)
		result.DurationMS = time.Since(start).Milliseconds()
		result.Error = newRedactor(req.Auth).Error(err)
		return result
	}
	req.Target = normalized

	runnerMu.RLock()
	runner := defaultRunner
	runnerMu.RUnlock()

	result, err := runner.Run(ctx, req)
	if result == nil {
		result = newResult(req)
	}
	if err != nil {
		result.OK = false
		result.Error = newRedactor(req.Auth).Error(err)
	}
	result.DurationMS = time.Since(start).Milliseconds()
	result.Stdout = truncateOutput(newRedactor(req.Auth).String(result.Stdout), req.Options.MaxOutputSize)
	result.Stderr = truncateOutput(newRedactor(req.Auth).String(result.Stderr), req.Options.MaxOutputSize)
	result.Error = newRedactor(req.Auth).String(result.Error)
	return result
}
