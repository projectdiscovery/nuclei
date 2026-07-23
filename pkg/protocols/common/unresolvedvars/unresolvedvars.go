package unresolvedvars

import (
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

const errSubstring = "unresolved variables"

// Is reports whether err is (or wraps) an unresolved-variables skip.
func Is(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), errSubstring)
}

// Skip records a request skipped due to unresolved variables and optionally logs it.
// Per-request warnings are muted unless options.LogUnresolved is set; use the end-of-scan
// summary from progress.SkippedUnresolved instead.
func Skip(prog progress.Progress, options *types.Options, templateID, target string, err error) {
	if prog != nil {
		prog.IncrementSkippedUnresolved(1)
	}
	if options != nil && options.LogUnresolved {
		gologger.Warning().Msgf("[%s] Could not make request for %s: %v\n", templateID, target, err)
	}
}
