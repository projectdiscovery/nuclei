package core

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// Engine is an executer for running Nuclei Templates/Workflows.
//
// The engine contains multiple thread pools which allow using different
// concurrency values per protocol executed.
//
// The engine does most of the heavy lifting of execution, from clustering
// templates to leading to the final execution by the work pool, it is
// handled by the engine.
type Engine struct {
	workPool     *WorkPool
	options      *types.Options
	executerOpts protocols.ExecutorOptions
	Callback     func(*output.ResultEvent) // Executed on results
}

// InputProvider is an input providing interface for the nuclei execution
// engine.
//
// An example InputProvider implementation is provided in form of hybrid
// input provider in pkg/core/inputs/hybrid/hmap.go
type InputProvider interface {
	// Count returns the number of items for input provider
	Count() int64
	// Scan iterates the input and each found item is passed to the
	// callback consumer.
	Scan(callback func(value *contextargs.MetaInput) bool)
	// Set adds item to input provider
	Set(value string)
}

// New returns a new Engine instance
func New(options *types.Options) *Engine {
	engine := &Engine{
		options: options,
	}
	engine.workPool = engine.GetWorkPool()
	return engine
}

// GetWorkPool returns a workpool from options
func (e *Engine) GetWorkPool() *WorkPool {
	return NewWorkPool(WorkPoolConfig{
		InputConcurrency:         e.options.BulkSize,
		TypeConcurrency:          e.options.TemplateThreads,
		HeadlessInputConcurrency: e.options.HeadlessBulkSize,
		HeadlessTypeConcurrency:  e.options.HeadlessTemplateThreads,
	})
}

// SetExecuterOptions sets the executer options for the engine. This is required
// before using the engine to perform any execution.
func (e *Engine) SetExecuterOptions(options protocols.ExecutorOptions) {
	e.executerOpts = options
}

// ExecuterOptions returns protocols.ExecutorOptions for nuclei engine.
func (e *Engine) ExecuterOptions() protocols.ExecutorOptions {
	return e.executerOpts
}

// WorkPool returns the worker pool for the engine
func (e *Engine) WorkPool() *WorkPool {
	return e.workPool
}
