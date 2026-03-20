package authx

import (
	"errors"
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

func TestDynamicFetchConcurrent(t *testing.T) {
	t.Run("all-waiters-block-until-done", func(t *testing.T) {
		const numGoroutines = 10
		wantErr := errors.New("auth fetch failed")
		fetchStarted := make(chan struct{})
		fetchUnblock := make(chan struct{})

		d := &Dynamic{
			TemplatePath: "test-template.yaml",
			Variables:    []KV{{Key: "username", Value: "test"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(_ *Dynamic) error {
			close(fetchStarted)
			<-fetchUnblock
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

		select {
		case <-fetchStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("fetch callback never started")
		}

		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
			t.Fatal("fetch callers returned before fetch completed")
		case <-time.After(25 * time.Millisecond):
		}

		close(fetchUnblock)
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("fetch callers did not complete in time")
		}

		for _, err := range results {
			require.ErrorIs(t, err, wantErr)
		}
	})

	t.Run("fetch-callback-runs-once", func(t *testing.T) {
		const numGoroutines = 20
		var callCount atomic.Int32
		errs := make(chan error, numGoroutines)
		barrier := make(chan struct{})

		d := &Dynamic{
			TemplatePath: "test-template.yaml",
			Variables:    []KV{{Key: "username", Value: "test"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
			callCount.Add(1)
			time.Sleep(20 * time.Millisecond)
			dynamic.Extracted = map[string]interface{}{"token": "secret-token"}
			return nil
		})

		var wg sync.WaitGroup
		wg.Add(numGoroutines)
		for i := 0; i < numGoroutines; i++ {
			go func() {
				defer wg.Done()
				<-barrier
				errs <- d.Fetch(false)
			}()
		}
		close(barrier)
		wg.Wait()
		close(errs)

		for err := range errs {
			require.NoError(t, err)
		}

		require.Equal(t, int32(1), callCount.Load(), "fetch callback must be called exactly once")
	})
}
