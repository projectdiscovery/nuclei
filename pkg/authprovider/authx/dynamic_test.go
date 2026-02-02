package authx

import (
	"sync"
	"sync/atomic"
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

// TestConcurrentFetch tests that concurrent Fetch() calls properly wait
// for the first fetch to complete, fixing the race condition in issue #6592
func TestConcurrentFetch(t *testing.T) {
	t.Run("concurrent-fetch-waits", func(t *testing.T) {
		var callCount atomic.Int32
		var fetchStarted atomic.Bool

		d := &Dynamic{
			TemplatePath: "test-template.yaml",
			Variables:    []KV{{Key: "test", Value: "value"}},
			Secret: &Secret{
				Type:    "BasicAuth",
				Domains: []string{"example.com"},
			},
			Extracted: make(map[string]interface{}),
		}

		// Set up a callback that simulates a slow authentication fetch
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			callCount.Add(1)
			fetchStarted.Store(true)
			// Simulate network delay
			time.Sleep(100 * time.Millisecond)
			// Set extracted values
			d.Extracted["token"] = "test-token"
			return nil
		})

		const numGoroutines = 10
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		// Start a barrier to ensure all goroutines start at roughly the same time
		startBarrier := make(chan struct{})

		// Track results from each goroutine
		errors := make([]error, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				defer wg.Done()
				<-startBarrier // Wait for signal to start
				errors[idx] = d.Fetch(false)
			}(i)
		}

		// Release all goroutines at once
		close(startBarrier)

		// Wait for all to complete
		wg.Wait()

		// Verify callback was called exactly once
		require.Equal(t, int32(1), callCount.Load(), "callback should be called exactly once")

		// Verify all goroutines got no error
		for i, err := range errors {
			require.NoError(t, err, "goroutine %d should have no error", i)
		}

		// Verify extracted values are available
		require.Equal(t, "test-token", d.Extracted["token"])
	})

	t.Run("get-strategies-waits-for-fetch", func(t *testing.T) {
		var callCount atomic.Int32

		d := &Dynamic{
			TemplatePath: "test-template.yaml",
			Variables:    []KV{{Key: "test", Value: "value"}},
			Secret: &Secret{
				Type:     "BasicAuth",
				Domains:  []string{"example.com"},
				Username: "user",
				Password: "pass",
			},
			Extracted: make(map[string]interface{}),
		}

		d.SetLazyFetchCallback(func(d *Dynamic) error {
			callCount.Add(1)
			time.Sleep(50 * time.Millisecond)
			d.Extracted["dummy"] = "value"
			return nil
		})

		const numGoroutines = 5
		var wg sync.WaitGroup
		wg.Add(numGoroutines)

		startBarrier := make(chan struct{})
		strategies := make([][]AuthStrategy, numGoroutines)

		for i := 0; i < numGoroutines; i++ {
			go func(idx int) {
				defer wg.Done()
				<-startBarrier
				strategies[idx] = d.GetStrategies()
			}(i)
		}

		close(startBarrier)
		wg.Wait()

		// Callback should be called exactly once
		require.Equal(t, int32(1), callCount.Load(), "callback should be called exactly once")

		// All goroutines should get valid strategies
		for i, strats := range strategies {
			require.NotNil(t, strats, "goroutine %d should get strategies", i)
			require.Len(t, strats, 1, "goroutine %d should get 1 strategy", i)
		}
	})
}
