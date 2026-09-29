package protocolstate

import (
	"context"

	"github.com/rs/xid"
)

// contextKey is a type for context keys
type ContextKey string

type ExecutionContext struct {
	ExecutionID string
}

// executionIDKey is the key used to store execution ID in context
const executionIDKey ContextKey = "execution_id"

// WithExecutionID adds an execution ID to the context
func WithExecutionID(ctx context.Context, executionContext *ExecutionContext) context.Context {
	return context.WithValue(ctx, executionIDKey, executionContext)
}

// HasExecutionID checks if the context has an execution ID
func HasExecutionContext(ctx context.Context) bool {
	_, ok := ctx.Value(executionIDKey).(*ExecutionContext)
	return ok
}

// GetExecutionID retrieves the execution ID from the context
// Returns empty string if no execution ID is set
func GetExecutionContext(ctx context.Context) *ExecutionContext {
	if id, ok := ctx.Value(executionIDKey).(*ExecutionContext); ok {
		return id
	}
	return nil
}

// WithAutoExecutionContext creates a new context with an automatically generated execution ID
// If the input context already has an execution ID, it will be preserved
func WithAutoExecutionContext(ctx context.Context) context.Context {
	if HasExecutionContext(ctx) {
		return ctx
	}
	return WithExecutionID(ctx, &ExecutionContext{ExecutionID: xid.New().String()})
}
