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

func TestConcurrentFetch(t *testing.T) {
	t.Run("concurrent-fetch-waits", func(t *testing.T) {
		var callCount atomic.Int32

		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{{Key: "Authorization", Value: "{{token}}"}},
			},
			TemplatePath: "test.yaml",
			Variables:    []KV{{Key: "username", Value: "test"}},
		}
		require.NoError(t, d.Validate())

		d.SetLazyFetchCallback(func(d *Dynamic) error {
			callCount.Add(1)
			// Simulate slow network fetch
			time.Sleep(100 * time.Millisecond)
			d.Extracted = map[string]interface{}{
				"token": "Bearer secret-token",
			}
			return nil
		})

		// Launch multiple goroutines that all call Fetch concurrently
		const numGoroutines = 10
		var wg sync.WaitGroup
		errs := make([]error, numGoroutines)

		// Use a barrier to ensure all goroutines start at the same time
		barrier := make(chan struct{})

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-barrier // wait for barrier
				errs[idx] = d.Fetch(false)
			}(i)
		}

		// Release all goroutines at once
		close(barrier)
		wg.Wait()

		// The fetch callback should have been called exactly once
		require.Equal(t, int32(1), callCount.Load(), "fetch callback should be called exactly once")

		// All goroutines should have received nil error
		for i, err := range errs {
			require.NoError(t, err, "goroutine %d should not have received an error", i)
		}

		// Verify the secret was properly populated
		strategies := d.GetStrategies()
		require.NotNil(t, strategies, "strategies should not be nil after fetch")
		require.Len(t, strategies, 1, "should have exactly one strategy")
	})
}
