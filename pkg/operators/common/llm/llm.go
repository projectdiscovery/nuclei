// Package llm holds the shared client used by llm matchers and extractors so a
// scan uses one configured provider (and therefore one cache, budget, and
// concurrency limit) across both.
package llm

import (
	"context"
	"sync"
)

// Client is the minimal surface an llm operator needs. It is intentionally
// decoupled from any provider SDK so operators can be unit-tested with a stub
// and the concrete client (backed by the shared provider layer) is injected at
// startup.
type Client interface {
	Complete(ctx context.Context, prompt string, asJSON bool) (string, error)
}

var (
	globalMu     sync.RWMutex
	globalClient Client
)

// SetGlobalClient installs the scan-wide client. A nil client disables llm
// operators, which then fail closed (no match / no extraction) rather than
// erroring.
func SetGlobalClient(client Client) {
	globalMu.Lock()
	defer globalMu.Unlock()
	globalClient = client
}

// GlobalClient returns the scan-wide client, or nil when llm is not enabled.
func GlobalClient() Client {
	globalMu.RLock()
	defer globalMu.RUnlock()

	return globalClient
}

// TruncateApproxTokens trims input to roughly maxTokens using the common
// 4-chars-per-token approximation. Exact counting is provider-specific; this
// only needs to keep a large body from blowing the context window.
func TruncateApproxTokens(input string, maxTokens int) string {
	if maxTokens <= 0 {
		return input
	}

	maxChars := maxTokens * 4
	if len(input) <= maxChars {
		return input
	}

	return input[:maxChars]
}
