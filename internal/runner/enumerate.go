package runner

import (
	_ "net/http/pprof"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
)

// runStandardEnumeration runs standard enumeration
func (r *Runner) runStandardEnumeration(executerOpts protocols.ExecutorOptions, store *loader.Store, engine *core.Engine) (*atomic.Bool, error) {
	if r.options.AutomaticScan {
		return r.executeSmartWorkflowInput(executerOpts, store, engine)
	}
	return r.executeTemplatesInput(store, engine)
}
