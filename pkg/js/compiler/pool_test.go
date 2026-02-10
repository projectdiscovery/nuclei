package compiler

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// TestExecuteWithOptions_ExpiredContext verifies that ExecuteWithOptions
// returns promptly when given an already-cancelled context, rather than
// blocking indefinitely on pool slot acquisition.
func TestExecuteWithOptions_ExpiredContext(t *testing.T) {
	compiler := New()
	p, err := SourceAutoMode("1 + 1", false)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, execErr := compiler.ExecuteWithOptions(p, NewExecuteArgs(), &ExecuteOptions{
			Context:         ctx,
			TimeoutVariants: &types.Timeouts{JsCompilerExecutionTimeout: 20 * time.Second},
		})
		if execErr == nil {
			t.Error("expected error from ExecuteWithOptions with cancelled context, got nil")
		}
	}()

	select {
	case <-done:
		// Good — returned promptly.
	case <-time.After(5 * time.Second):
		t.Fatal("ExecuteWithOptions blocked for >5s with a cancelled context; pool starvation bug")
	}
}

// TestExecuteWithOptions_DeadlineRespected verifies that a tight deadline
// causes ExecuteWithOptions to return with a deadline error instead of
// blocking on pool acquisition.
func TestExecuteWithOptions_DeadlineRespected(t *testing.T) {
	compiler := New()
	// A script that would take a long time if actually run
	p, err := SourceAutoMode("1 + 1", false)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()
	time.Sleep(5 * time.Millisecond) // let it expire

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, execErr := compiler.ExecuteWithOptions(p, NewExecuteArgs(), &ExecuteOptions{
			Context:         ctx,
			TimeoutVariants: &types.Timeouts{JsCompilerExecutionTimeout: 20 * time.Second},
		})
		if execErr == nil {
			t.Error("expected error from ExecuteWithOptions with expired deadline, got nil")
		}
	}()

	select {
	case <-done:
		// Good — returned promptly.
	case <-time.After(5 * time.Second):
		t.Fatal("ExecuteWithOptions blocked for >5s with an expired deadline; pool starvation bug")
	}
}
