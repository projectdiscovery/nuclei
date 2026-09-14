// Package llm holds the shared client used by llm matchers and extractors so a
// scan uses one configured provider (and therefore one cache, budget, and
// concurrency limit) across both.
package llm

import (
	"context"
)

// Client is the minimal surface an llm operator needs. It is intentionally
// decoupled from any provider SDK so operators can be unit-tested with a stub
// and the concrete client (backed by the shared provider layer) is injected at
// startup.
type Client interface {
	Complete(ctx context.Context, prompt string, asJSON bool) (string, error)
}

// TruncateApproxTokens trims input to roughly maxTokens using the common
// 4-chars-per-token approximation. Exact counting is provider-specific; this
// only needs to keep a large body from blowing the context window.
func TruncateApproxTokens(input string, maxTokens int) string {
	if maxTokens <= 0 {
		return input
	}

	// Compare by division so a large max-input-tokens cannot overflow int and
	// produce a negative slice bound.
	if maxTokens >= len(input)/4+1 {
		return input
	}

	return input[:maxTokens*4]
}
