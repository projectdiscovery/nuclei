package core

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/cruisecontrol"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
)

// WorkPool implements an execution pool for executing different
// types of task with different concurrency requirements.
//
// It also allows Configuration of such requirements. This is used
// for per-module like separate headless concurrency etc.
type WorkPool struct {
	Headless      *cruisecontrol.CruiseControlPool
	Default       *cruisecontrol.CruiseControlPool
	cruiseControl *cruisecontrol.CruiseControl
}

// NewWorkPool returns a new WorkPool instance
func NewWorkPool(cruiseControl *cruisecontrol.CruiseControl) *WorkPool {
	headlessPool := cruiseControl.NewPool(cruiseControl.HeadlessTemplates)
	defaultPool := cruiseControl.NewPool(cruiseControl.StandardTemplates)

	return &WorkPool{
		cruiseControl: cruiseControl,
		Headless:      headlessPool,
		Default:       defaultPool,
	}
}

// Wait waits for all the work pool wait groups to finish
func (w *WorkPool) Wait() {
	w.Default.Wait()
	w.Headless.Wait()
}

// InputPool returns a work pool for an input type
func (w *WorkPool) InputPool(templateType types.ProtocolType) *cruisecontrol.CruiseControlPool {
	switch templateType {
	case types.HeadlessProtocol:
		return w.cruiseControl.NewPool(w.cruiseControl.HeadlessHosts)
	default:
		return w.cruiseControl.NewPool(w.cruiseControl.StandardHosts)
	}
}
