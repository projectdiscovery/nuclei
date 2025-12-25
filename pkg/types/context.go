package types

import (
	"context"

	"github.com/projectdiscovery/gologger"
)

// ApplyMaxTimeContext applies MaxTime timeout to the given context if MaxTime is set in options.
// If the context already has a deadline, it returns the original context unchanged.
// Returns the context (possibly with timeout), a cancel function (which should be deferred), and a boolean indicating if timeout was applied.
func ApplyMaxTimeContext(ctx context.Context, opts *Options, logger *gologger.Logger) (context.Context, context.CancelFunc, bool) {
	if opts.MaxTime <= 0 {
		return ctx, nil, false
	}

	if _, hasDeadline := ctx.Deadline(); hasDeadline {
		return ctx, nil, false
	}

	execCtx, cancel := context.WithTimeout(ctx, opts.MaxTime)
	go func() {
		<-execCtx.Done()
		if execCtx.Err() == context.DeadlineExceeded && logger != nil {
			logger.Info().Msgf("Maximum execution time of %s reached. Gracefully stopping scan...", opts.MaxTime)
		}
	}()

	return execCtx, cancel, true
}
