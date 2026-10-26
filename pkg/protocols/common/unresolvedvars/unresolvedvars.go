package unresolvedvars

import (
	"errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/progress"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/expressions"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Is reports whether err is (or wraps) an unresolved-variables error.
func Is(err error) bool {
	return errors.Is(err, expressions.ErrUnresolvedVariables)
}

// Skip records a request skipped due to unresolved variables and optionally logs it.
// Per-request warnings are muted unless options.LogUnresolved is set; use the end-of-scan
// summary from progress.UnresolvedCounter instead.
func Skip(prog progress.Progress, options *types.Options, templateID, target string, err error) {
	if counter, ok := prog.(progress.UnresolvedCounter); ok {
		counter.IncrementSkippedUnresolved(1)
	}
	// The user asked for these lines, so they are logged at info level: the
	// default log level hides warnings unless -v is set.
	if options == nil || !options.LogUnresolved {
		return
	}
	// self-contained requests have no input target
	if target == "" {
		gologger.Info().Msgf("[%s] Could not make request: %v\n", templateID, err)
		return
	}
	gologger.Info().Msgf("[%s] Could not make request for %s: %v\n", templateID, target, err)
}
