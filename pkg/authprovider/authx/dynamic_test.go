package authx

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestDynamicFetchConcurrent verifies that concurrent calls to Fetch()
// block until the single fetch completes — no caller slips through with
// un-populated secrets. This is the regression test for #6592.
func TestDynamicFetchConcurrent(t *testing.T) {
	t.Run("all-waiters-block-until-done", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "test.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		// Validate initialises fetchOnce
		if err := d.Validate(); err != nil {
			t.Fatal(err)
		}

		var callCount atomic.Int32
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			callCount.Add(1)
			time.Sleep(100 * time.Millisecond) // simulate slow auth
			d.Extracted = map[string]interface{}{"token": "abc123"}
			return nil
		})

		const workers = 20
		var wg sync.WaitGroup
		errs := make([]error, workers)

		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func(idx int) {
				defer wg.Done()
				errs[idx] = d.Fetch(false)
			}(i)
		}
		wg.Wait()

		// Callback must have run exactly once
		if n := callCount.Load(); n != 1 {
			t.Fatalf("expected fetch callback to run once, got %d", n)
		}

		// All workers must see nil error
		for i, err := range errs {
			if err != nil {
				t.Fatalf("worker %d got unexpected error: %v", i, err)
			}
		}

		// Extracted values must be populated
		if d.Extracted["token"] != "abc123" {
			t.Fatalf("expected extracted token 'abc123', got %v", d.Extracted["token"])
		}
	})

	t.Run("fetch-not-validated-returns-error", func(t *testing.T) {
		d := &Dynamic{} // fetchOnce is nil
		err := d.Fetch(false)
		if err == nil {
			t.Fatal("expected error for unvalidated Dynamic, got nil")
		}
	})
}
