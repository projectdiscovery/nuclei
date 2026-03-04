package authx

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/projectdiscovery/utils/errkit"
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

// TestDynamicFetchRaceCondition tests that concurrent calls to GetStrategies
// do not result in a race condition where some callers return nil before
// the fetch completes. This is the fix for Issue #6592.
func TestDynamicFetchRaceCondition(t *testing.T) {
	t.Run("concurrent-get-strategies", func(t *testing.T) {
		// Create a dynamic secret with a slow fetch callback
		d := &Dynamic{
			Secret: &Secret{
				Type:    "BearerToken",
				Domains: []string{"example.com"},
				Token:   "initial",
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "Bearer token"},
			},
		}

		// Validate initializes the sync.Once
		err := d.Validate()
		require.NoError(t, err)

		fetchCalled := atomic.Int32{}
		fetchCompleted := atomic.Int32{}

		// Set a slow fetch callback that simulates network delay
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			fetchCalled.Add(1)
			// Simulate slow network request
			time.Sleep(100 * time.Millisecond)
			d.Extracted = map[string]interface{}{"token": "extracted-token"}
			d.Token = "extracted-token"
			fetchCompleted.Add(1)
			return nil
		})

		// Launch multiple concurrent goroutines calling GetStrategies
		const goroutines = 20
		var wg sync.WaitGroup
		results := make([][]AuthStrategy, goroutines)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = d.GetStrategies()
			}(i)
		}

		wg.Wait()

		// Verify fetch was called exactly once
		require.Equal(t, int32(1), fetchCalled.Load(), "fetch should be called exactly once")
		require.Equal(t, int32(1), fetchCompleted.Load(), "fetch should complete exactly once")

		// Verify ALL goroutines received the same non-nil strategies
		for i, result := range results {
			require.NotNil(t, result, "goroutine %d should receive non-nil strategies", i)
			require.Len(t, result, 1, "goroutine %d should receive exactly 1 strategy", i)
		}

		// Verify the token was properly extracted and applied
		require.Equal(t, "extracted-token", d.Token, "token should be updated after fetch")
	})

	t.Run("concurrent-fetch-with-error", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "BearerToken",
				Domains: []string{"example.com"},
				Token:   "initial",
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "Bearer token"},
			},
		}

		err := d.Validate()
		require.NoError(t, err)

		fetchCalled := atomic.Int32{}

		// Set a fetch callback that returns an error
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			fetchCalled.Add(1)
			time.Sleep(50 * time.Millisecond)
			return errkit.New("fetch failed intentionally")
		})

		const goroutines = 10
		var wg sync.WaitGroup
		results := make([][]AuthStrategy, goroutines)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx] = d.GetStrategies()
			}(i)
		}

		wg.Wait()

		// Verify fetch was called exactly once
		require.Equal(t, int32(1), fetchCalled.Load(), "fetch should be called exactly once")

		// Verify ALL goroutines received nil strategies due to error
		for i, result := range results {
			require.Nil(t, result, "goroutine %d should receive nil strategies on error", i)
		}

		// Verify error is recorded
		require.Error(t, d.Error(), "error should be recorded")
	})

	t.Run("concurrent-fetch-blocks-until-complete", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "BearerToken",
				Domains: []string{"example.com"},
				Token:   "initial",
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "Bearer token"},
			},
		}

		err := d.Validate()
		require.NoError(t, err)

		var fetchStarted sync.WaitGroup
		fetchStarted.Add(1)

		d.SetLazyFetchCallback(func(d *Dynamic) error {
			fetchStarted.Done() // Signal that fetch has started
			// Wait until all callers are blocked
			time.Sleep(100 * time.Millisecond)
			d.Extracted = map[string]interface{}{"token": "extracted"}
			d.Token = "extracted"
			return nil
		})

		const goroutines = 10
		var wg sync.WaitGroup
		allGotResults := atomic.Int32{}

		// Start one goroutine first to trigger fetch
		wg.Add(1)
		go func() {
			defer wg.Done()
			result := d.GetStrategies()
			if result != nil {
				allGotResults.Add(1)
			}
		}()

		// Wait for fetch to start
		fetchStarted.Wait()

		// Now start the rest of the goroutines
		for i := 1; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				result := d.GetStrategies()
				if result != nil {
					allGotResults.Add(1)
				}
			}(i)
		}

		wg.Wait()

		// All goroutines should have received results after fetch completed
		require.Equal(t, int32(goroutines), allGotResults.Load(),
			"all goroutines should have received results after fetch completed")
		require.Equal(t, "extracted", d.Token, "token should be updated after fetch")
	})
}

// TestDynamicFetchAndHydrateIntegration tests that fetch and hydration are
// atomically combined under a single sync.Once guard. This ensures that
// template variables (e.g., {{token}}) are properly replaced with extracted
// values BEFORE any strategies are returned.
// This is the CRITICAL fix that prevents unhydrated secrets from being used.
func TestDynamicFetchAndHydrateIntegration(t *testing.T) {
	t.Run("hydration-occurs-before-strategies-returned", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{
					{Key: "Authorization", Value: "Bearer {{token}}"},
				},
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "placeholder"},
			},
		}

		require.NoError(t, d.Validate())

		// Set fetch callback that extracts a token value
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			d.Extracted = map[string]interface{}{"token": "actual-secret-token"}
			return nil
		})

		// Get strategies should trigger fetch AND hydration
		strategies := d.GetStrategies()

		require.NotNil(t, strategies, "strategies should not be nil")
		require.Len(t, strategies, 1, "should have 1 strategy")

		// Verify the header value was hydrated (not still {{token}})
		secret := d.Secret
		require.NotNil(t, secret)
		require.Len(t, secret.Headers, 1)
		require.Equal(t, "Bearer actual-secret-token", secret.Headers[0].Value,
			"header value should be hydrated with actual token")
	})

	t.Run("fetch-then-getstrategies-returns-hydrated-secret", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{
					{Key: "Authorization", Value: "Bearer {{token}}"},
				},
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "placeholder"},
			},
		}

		require.NoError(t, d.Validate())

		// Set fetch callback
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			d.Extracted = map[string]interface{}{"token": "from-fetch"}
			return nil
		})

		// Call Fetch first (simulating pre-fetch scenario)
		err := d.Fetch()
		require.NoError(t, err)

		// Now call GetStrategies - should return hydrated secret
		strategies := d.GetStrategies()

		require.NotNil(t, strategies, "strategies should not be nil")

		// Verify hydration occurred even though Fetch was called first
		secret := d.Secret
		require.NotNil(t, secret)
		require.Len(t, secret.Headers, 1)
		require.Equal(t, "Bearer from-fetch", secret.Headers[0].Value,
			"header value should be hydrated even after Fetch() called first")
	})

	t.Run("getstrategies-then-fetch-both-return-hydrated", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{
					{Key: "Authorization", Value: "Bearer {{token}}"},
				},
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "placeholder"},
			},
		}

		require.NoError(t, d.Validate())

		callCount := atomic.Int32{}
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			callCount.Add(1)
			d.Extracted = map[string]interface{}{"token": "hydrated-value"}
			return nil
		})

		// Call GetStrategies first
		strategies1 := d.GetStrategies()
		require.NotNil(t, strategies1)

		// Verify hydration
		require.Equal(t, "Bearer hydrated-value", d.Secret.Headers[0].Value)

		// Call Fetch again - should NOT call callback again (sync.Once)
		err := d.Fetch()
		require.NoError(t, err)

		// Verify callback was only called once
		require.Equal(t, int32(1), callCount.Load(), "fetch callback should only be called once")

		// Verify hydration still correct
		require.Equal(t, "Bearer hydrated-value", d.Secret.Headers[0].Value)
	})

	t.Run("concurrent-fetch-and-getstrategies-all-hydrated", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{
					{Key: "Authorization", Value: "Bearer {{token}}"},
				},
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "placeholder"},
			},
		}

		require.NoError(t, d.Validate())

		fetchStarted := make(chan struct{})
		fetchCompleted := make(chan struct{})

		d.SetLazyFetchCallback(func(d *Dynamic) error {
			close(fetchStarted)
			time.Sleep(50 * time.Millisecond) // Simulate network delay
			d.Extracted = map[string]interface{}{"token": "concurrent-token"}
			close(fetchCompleted)
			return nil
		})

		const goroutines = 15
		var wg sync.WaitGroup
		results := make([]struct {
			strategies []AuthStrategy
			headerVal  string
		}, goroutines)

		for i := 0; i < goroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				results[idx].strategies = d.GetStrategies()
				if d.Secret != nil && len(d.Secret.Headers) > 0 {
					results[idx].headerVal = d.Secret.Headers[0].Value
				}
			}(i)
		}

		wg.Wait()

		// Wait for fetch to complete
		<-fetchCompleted
		<-time.After(10 * time.Millisecond)

		// Verify ALL goroutines got hydrated values
		for i, result := range results {
			require.NotNil(t, result.strategies, "goroutine %d should have strategies", i)
			require.Equal(t, "Bearer concurrent-token", result.headerVal,
				"goroutine %d should have hydrated header value", i)
		}

		// Final verification
		require.Equal(t, "Bearer concurrent-token", d.Secret.Headers[0].Value)
	})
}

// TestDynamicFetchRetryOnError tests that fetch can be retried after failure
// This verifies that sync.Once is reset on error, allowing retry
func TestDynamicFetchRetryOnError(t *testing.T) {
	t.Run("retry-after-fetch-error", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{
					{Key: "Authorization", Value: "Bearer {{token}}"},
				},
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "placeholder"},
			},
		}

		require.NoError(t, d.Validate())

		callCount := atomic.Int32{}
		fetchErr := errkit.New("temporary network error")

		// First call fails
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			callCount.Add(1)
			if callCount.Load() == 1 {
				return fetchErr
			}
			// Second call succeeds
			d.Extracted = map[string]interface{}{"token": "success-token"}
			return nil
		})

		// First call should fail
		err := d.Fetch()
		require.Error(t, err)
		require.ErrorIs(t, err, fetchErr)
		require.Equal(t, int32(1), callCount.Load())

		// Second call should succeed (retry allowed)
		err = d.Fetch()
		require.NoError(t, err)
		require.Equal(t, int32(2), callCount.Load())

		// Verify hydration occurred
		require.Equal(t, "Bearer success-token", d.Secret.Headers[0].Value)
	})

	t.Run("manual-reset-allows-refetch", func(t *testing.T) {
		// Note: Reset() clears fetch state but does not restore original template values
		// This is expected behavior - after Reset(), you should re-initialize the Secret
		// if you need to re-fetch with fresh template variables
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{
					{Key: "Authorization", Value: "Bearer {{token}}"},
				},
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "placeholder"},
			},
		}

		require.NoError(t, d.Validate())

		callCount := atomic.Int32{}
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			callCount.Add(1)
			d.Extracted = map[string]interface{}{"token": fmt.Sprintf("token-%d", callCount.Load())}
			return nil
		})

		// First fetch
		strategies1 := d.GetStrategies()
		require.NotNil(t, strategies1)
		require.Equal(t, "Bearer token-1", d.Secret.Headers[0].Value)
		require.Equal(t, int32(1), callCount.Load())

		// Reset and fetch again - note that Headers[0].Value is now "Bearer token-1"
		// so re-hydration won't change it unless we restore the template
		d.Reset()
		require.False(t, d.IsFetched(), "should not be fetched after reset")

		// For proper re-fetch, we need to restore the template value
		d.Secret.Headers[0] = KV{Key: "Authorization", Value: "Bearer {{token}}"}

		strategies2 := d.GetStrategies()
		require.NotNil(t, strategies2)
		require.Equal(t, "Bearer token-2", d.Secret.Headers[0].Value)
		require.Equal(t, int32(2), callCount.Load())
	})

	t.Run("no-retry-after-success", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{
					{Key: "Authorization", Value: "Bearer {{token}}"},
				},
			},
			TemplatePath: "test-template.yaml",
			Variables: []KV{
				{Key: "token", Value: "placeholder"},
			},
		}

		require.NoError(t, d.Validate())

		callCount := atomic.Int32{}
		d.SetLazyFetchCallback(func(d *Dynamic) error {
			callCount.Add(1)
			d.Extracted = map[string]interface{}{"token": "success-token"}
			return nil
		})

		// First call succeeds
		strategies1 := d.GetStrategies()
		require.NotNil(t, strategies1)
		require.Equal(t, int32(1), callCount.Load())

		// Second call should NOT call callback again (sync.Once)
		strategies2 := d.GetStrategies()
		require.NotNil(t, strategies2)
		require.Equal(t, int32(1), callCount.Load(), "callback should only be called once on success")

		// Verify same result
		require.Equal(t, "Bearer success-token", d.Secret.Headers[0].Value)
	})
}
