package core

import (
	"github.com/remeh/sizedwaitgroup"
)

// WorkPool implements an execution pool for executing different
// types of task with different concurreny requirements.
//
// It also allows Configuration of such requirements. This is used
// for per-module like separate headless concurrency etc.
type WorkPool struct {
	Headless *sizedwaitgroup.SizedWaitGroup
	Default  *sizedwaitgroup.SizedWaitGroup
	config   WorkPoolConfig
}

// WorkPoolConfig is the configuration for workpool
type WorkPoolConfig struct {
	// InputConcurrency is the concurrency for inputs values.
	InputConcurrency int
	// TypeConcurrency is the concurrency for the request type templates.
	TypeConcurrency int
	// HeadlessInputConcurrency is the concurrency for headless inputs values.
	HeadlessInputConcurrency int
	// TypeConcurrency is the concurrency for the headless request type templates.
	HeadlessTypeConcurrency int
}

// NewWorkPool returns a new WorkPool instance
func NewWorkPool(config WorkPoolConfig) *WorkPool {
	headlessWg := sizedwaitgroup.New(config.HeadlessTypeConcurrency)
	defaultWg := sizedwaitgroup.New(config.TypeConcurrency)

	return &WorkPool{
		config:   config,
		Headless: &headlessWg,
		Default:  &defaultWg,
	}
}

// Wait waits for all the workpool waitgroups to finish
func (w *WorkPool) Wait() {
	w.Default.Wait()
	w.Headless.Wait()
}

// InputWorkPool is a workpool per-input
type InputWorkPool struct {
	Waitgroup *sizedwaitgroup.SizedWaitGroup
}

// InputPool returns a workpool for an input type
func (w *WorkPool) InputPool(templateType string) *InputWorkPool {
	var count int
	if templateType == "headless" {
		count = w.config.HeadlessInputConcurrency
	} else {
		count = w.config.InputConcurrency
	}
	swg := sizedwaitgroup.New(count)
	return &InputWorkPool{Waitgroup: &swg}
}
