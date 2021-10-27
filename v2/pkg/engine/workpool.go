package engine

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
)

// WorkPool implements an execution pool for executing different
// types of task with different concurreny requirements.
//
// It also allows Configuration of such requirements. This is used
// for per-module like separate headless concurrency etc.
type WorkPool struct {
	config WorkPoolConfig
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

// New returns a new WorkPool instance
func New(config WorkPoolConfig) *WorkPool {
	return &WorkPool{config: config}
}

// TODO: port these invocations of waitgroups and input logic into a generic
// workpool type functionality.
func (w *WorkPool) Execute(templates []*templates.Template) {

}
