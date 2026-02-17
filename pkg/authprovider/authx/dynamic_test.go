package authx

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDynamicUnmarshalJSON(t *testing.T) {
	t.Run("basic-unmarshal", func(t *testing.T) {
		data := []byte(`{
			"template": "test-template.yaml",
			"variables": [
				{
					"key": "username",
					"value": "testuser"
				}
			],
			"secrets": [
				{
					"type": "BasicAuth",
					"domains": ["example.com"],
					"username": "user1",
					"password": "pass1"
				}
			],
			"type": "BasicAuth",
			"domains": ["test.com"],
			"username": "testuser",
			"password": "testpass"
		}`)

		var d Dynamic
		err := d.UnmarshalJSON(data)
		require.NoError(t, err)

		// Secret
		require.NotNil(t, d.Secret)
		require.Equal(t, "BasicAuth", d.Type)
		require.Equal(t, []string{"test.com"}, d.Domains)
		require.Equal(t, "testuser", d.Username)
		require.Equal(t, "testpass", d.Password)

		// Dynamic fields
		require.Equal(t, "test-template.yaml", d.TemplatePath)
		require.Len(t, d.Variables, 1)
		require.Equal(t, "username", d.Variables[0].Key)
		require.Equal(t, "testuser", d.Variables[0].Value)
		require.Len(t, d.Secrets, 1)
		require.Equal(t, "BasicAuth", d.Secrets[0].Type)
		require.Equal(t, []string{"example.com"}, d.Secrets[0].Domains)
		require.Equal(t, "user1", d.Secrets[0].Username)
		require.Equal(t, "pass1", d.Secrets[0].Password)
	})

	t.Run("complex-unmarshal", func(t *testing.T) {
		data := []byte(`{
			"template": "test-template.yaml",
			"variables": [
				{
					"key": "token",
					"value": "Bearer xyz"
				}
			],
			"secrets": [
				{
					"type": "CookiesAuth",
					"domains": ["example.com"],
					"cookies": [
						{
							"key": "session",
							"value": "abc123"
						}
					]
				}
			],
			"type": "HeadersAuth",
			"domains": ["api.test.com"],
			"headers": [
				{
					"key": "X-API-Key",
					"value": "secret-key"
				}
			]
		}`)

		var d Dynamic
		err := d.UnmarshalJSON(data)
		require.NoError(t, err)

		// Secret
		require.NotNil(t, d.Secret)
		require.Equal(t, "HeadersAuth", d.Type)
		require.Equal(t, []string{"api.test.com"}, d.Domains)
		require.Len(t, d.Headers, 1)
		require.Equal(t, "X-API-Key", d.Secret.Headers[0].Key)
		require.Equal(t, "secret-key", d.Secret.Headers[0].Value)

		// Dynamic fields
		require.Equal(t, "test-template.yaml", d.TemplatePath)
		require.Len(t, d.Variables, 1)
		require.Equal(t, "token", d.Variables[0].Key)
		require.Equal(t, "Bearer xyz", d.Variables[0].Value)
		require.Len(t, d.Secrets, 1)
		require.Equal(t, "CookiesAuth", d.Secrets[0].Type)
		require.Equal(t, []string{"example.com"}, d.Secrets[0].Domains)
		require.Len(t, d.Secrets[0].Cookies, 1)
		require.Equal(t, "session", d.Secrets[0].Cookies[0].Key)
		require.Equal(t, "abc123", d.Secrets[0].Cookies[0].Value)
	})

	t.Run("invalid-json", func(t *testing.T) {
		data := []byte(`{invalid json}`)
		var d Dynamic
		err := d.UnmarshalJSON(data)
		require.Error(t, err)
	})

	t.Run("empty-json", func(t *testing.T) {
		data := []byte(`{}`)
		var d Dynamic
		err := d.UnmarshalJSON(data)
		require.NoError(t, err)
	})
}

// TestDynamicFetchConcurrent verifies that when multiple goroutines call Fetch()
// simultaneously, they all block until the fetch completes and all receive the
// same result — no goroutine returns prematurely with a nil error (issue #6592).
func TestDynamicFetchConcurrent(t *testing.T) {
	t.Run("all-waiters-block-until-done", func(t *testing.T) {
		const numGoroutines = 10
		fetchStarted := make(chan struct{})
		fetchUnblock := make(chan struct{})

		d := &Dynamic{
			TemplatePath: "test.yaml",
			Variables:    []KV{{Key: "k", Value: "v"}},
		}
		require.NoError(t, d.Validate())

		wantErr := errors.New("auth-fetch-error")

		// Slow callback: signals when it starts, then waits to be unblocked.
		d.SetLazyFetchCallback(func(dyn *Dynamic) error {
			close(fetchStarted) // signal that fetch has begun
			<-fetchUnblock      // wait until test says to proceed
			dyn.Extracted = map[string]interface{}{"k": "v"}
			return wantErr
		})

		results := make([]error, numGoroutines)
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				defer wg.Done()
				results[idx] = d.Fetch(false)
			}(i)
		}

		// Wait until the fetch callback has started (one goroutine is inside).
		select {
		case <-fetchStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("fetch callback never started")
		}

		// At this point all other goroutines should be blocking, not returning.
		// Give them a moment to reach their wait point.
		time.Sleep(20 * time.Millisecond)

		// Unblock the fetch.
		close(fetchUnblock)

		// Wait for all goroutines to finish.
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("goroutines did not complete in time")
		}

		// Every goroutine must have received the same error — not nil.
		for i, err := range results {
			require.Equal(t, wantErr, err, "goroutine %d got wrong error", i)
		}
	})

	t.Run("no-double-fetch", func(t *testing.T) {
		callCount := 0
		var mu sync.Mutex

		d := &Dynamic{
			TemplatePath: "test.yaml",
			Variables:    []KV{{Key: "k", Value: "v"}},
		}
		require.NoError(t, d.Validate())

		d.SetLazyFetchCallback(func(dyn *Dynamic) error {
			mu.Lock()
			callCount++
			mu.Unlock()
			dyn.Extracted = map[string]interface{}{"k": "v"}
			return nil
		})

		var wg sync.WaitGroup
		for i := 0; i < 20; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = d.Fetch(false)
			}()
		}
		wg.Wait()

		mu.Lock()
		count := callCount
		mu.Unlock()
		require.Equal(t, 1, count, "fetchCallback must be called exactly once")
	})
}
