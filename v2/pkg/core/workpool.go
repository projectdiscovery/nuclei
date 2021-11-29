package core

import (
	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

// WorkPool implements an execution pool for executing different
// types of task with different concurrency requirements.
//
// It also allows Configuration of such requirements. This is used
// for per-module like separate headless concurrency etc.
type WorkPool struct {
	Headless *sizedwaitgroup.SizedWaitGroup
	Default  *sizedwaitgroup.SizedWaitGroup
	config   WorkPoolConfig
}

// WorkPoolConfig is the configuration for work pool
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

// Wait waits for all the work pool wait groups to finish
func (w *WorkPool) Wait() {
	w.Default.Wait()
	w.Headless.Wait()
}

// InputWorkPool is a work pool per-input
type InputWorkPool struct {
	WaitGroup *sizedwaitgroup.SizedWaitGroup
}

// InputPool returns a work pool for an input type
func (w *WorkPool) InputPool(templateType types.ProtocolType) *InputWorkPool {
	var count int
	if templateType == types.HeadlessProtocol {
		count = w.config.HeadlessInputConcurrency
	} else {
		count = w.config.InputConcurrency
	}
	swg := sizedwaitgroup.New(count)
	return &InputWorkPool{WaitGroup: &swg}
}
