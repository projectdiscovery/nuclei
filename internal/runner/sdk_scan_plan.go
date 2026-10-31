package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/http/httprespcache"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// AttachScanPlan applies -strict-probe and -tech-filter to an SDK engine for
// one scan, the same way the CLI runner does. It returns a func that undoes the
// per-scan state; call it once the scan is done. When neither option is set it
// does nothing, so default SDK scans keep their behavior.
func AttachScanPlan(opts *types.Options, inputProvider provider.InputProvider, logger *gologger.Logger, engine *core.Engine, tpls []*templates.Template) func() {
	if opts == nil || engine == nil || inputProvider == nil || (!opts.StrictProbe && !opts.TechFilter) {
		return func() {}
	}
	if logger == nil {
		logger = gologger.DefaultLogger
	}
	// The SDK engine is reused across scans, so keep the options and the
	// response cache it owns as they were before this scan.
	strategy := opts.ScanStrategy
	executerOpts := engine.ExecuterOptions()
	var responseCache *httprespcache.Cache
	if executerOpts != nil {
		responseCache = executerOpts.HTTPResponseCache
	}
	r := &Runner{options: opts, inputProvider: inputProvider, Logger: logger}
	cleanup := r.attachScanPlan(engine, tpls)
	return func() {
		cleanup()
		opts.ScanStrategy = strategy
		if executerOpts != nil {
			executerOpts.HTTPResponseCache = responseCache
		}
	}
}
