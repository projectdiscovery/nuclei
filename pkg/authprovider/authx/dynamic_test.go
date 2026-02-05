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

// TestConcurrentFetch tests that concurrent calls to Fetch wait for the first
// fetch to complete instead of returning immediately with no auth credentials.
// This is a regression test for https://github.com/projectdiscovery/nuclei/issues/6592
func TestConcurrentFetch(t *testing.T) {
	d := &Dynamic{
		Secret: &Secret{
			Type:    "Cookie",
			Domains: []string{"example.com"},
			Cookies: []Cookie{{Key: "session", Value: "{{token}}"}},
		},
		TemplatePath: "test.yaml",
		Variables:    []KV{{Key: "user", Value: "test"}},
	}

	// Initialize the dynamic secret (normally done by Validate)
	require.NoError(t, d.Validate())

	var fetchCount atomic.Int32
	fetchStarted := make(chan struct{})
	fetchComplete := make(chan struct{})

	// Set up a callback that simulates a slow fetch
	d.SetLazyFetchCallback(func(d *Dynamic) error {
		fetchCount.Add(1)
		close(fetchStarted) // Signal that fetch has started
		<-fetchComplete     // Wait for signal to complete
		d.Extracted = map[string]interface{}{
			"token": "extracted-token",
		}
		return nil
	})

	const numGoroutines = 10
	var wg sync.WaitGroup
	results := make([]error, numGoroutines)
	allStarted := make(chan struct{})

	// Launch multiple goroutines that will all try to fetch concurrently
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-allStarted // Wait for all goroutines to be ready
			results[idx] = d.Fetch(false)
		}(i)
	}

	// Start all goroutines at once
	close(allStarted)

	// Wait for the fetch to start
	select {
	case <-fetchStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("fetch did not start within timeout")
	}

	// Give goroutines time to attempt concurrent fetch
	time.Sleep(100 * time.Millisecond)

	// Complete the fetch
	close(fetchComplete)

	// Wait for all goroutines to finish
	wg.Wait()

	// Verify the callback was only called once
	require.Equal(t, int32(1), fetchCount.Load(), "fetch callback should only be called once")

	// Verify all goroutines received no error
	for i, err := range results {
		require.NoError(t, err, "goroutine %d should have no error", i)
	}

	// Verify the extracted value is available
	require.Equal(t, "extracted-token", d.Extracted["token"])
}
