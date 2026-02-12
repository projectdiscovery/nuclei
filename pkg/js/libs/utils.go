package libs

import (
	"context"
	"sync"
)

var dialContexts sync.Map

// SetDialContext stores the execution context for a given executionId.
// This is called by the JS compiler before running a script.
// Used as a fallback for @memo functions that only have executionId.
func SetDialContext(executionId string, ctx context.Context) {
	dialContexts.Store(executionId, ctx)
}

// RemoveDialContext removes the stored execution context for the given executionId.
// This should be called during cleanup to prevent memory leaks.
func RemoveDialContext(executionId string) {
	dialContexts.Delete(executionId)
}

// GetDialContext returns the execution context for network dials.
// It accepts either a context.Context (the goja runtime context) or
// a string (executionId) for backward compatibility with @memo functions.
//
// When passed a goja context, it extracts the per-execution context
// stored by the JS compiler — this is the correct, race-free path.
// When passed an executionId string, it falls back to a shared map
// which is acceptable for @memo functions (cached, first-call-only).
func GetDialContext(key any) context.Context {
	switch v := key.(type) {
	case context.Context:
		if execCtx, ok := v.Value("ctx").(context.Context); ok {
			return execCtx
		}
		// Fall back to the caller's context rather than a bare Background,
		// so at least the parent's cancellation is respected.
		return v
	case string:
		if val, ok := dialContexts.Load(v); ok {
			return val.(context.Context)
		}
		return context.Background()
	default:
		return context.Background()
	}
}