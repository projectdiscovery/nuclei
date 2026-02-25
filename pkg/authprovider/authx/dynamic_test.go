package authx

import (
	"sync"
	"sync/atomic"
	"testing"

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

func TestDynamicFetchConcurrent(t *testing.T) {
	t.Run("fetch-callback-runs-once", func(t *testing.T) {
		var callCount atomic.Int32
		var completed atomic.Int32
		ready := make(chan struct{})
		entered := make(chan struct{})

		d := &Dynamic{
			TemplatePath: "test.yaml",
			Variables:    []KV{{Key: "k", Value: "v"}},
		}
		require.NoError(t, d.Validate())
		d.fetchCallback = func(_ *Dynamic) error {
			close(entered) // signal: winner goroutine is inside the callback
			<-ready
			callCount.Add(1)
			return nil
		}

		var wg sync.WaitGroup
		const n = 20
		wg.Add(n)
		for i := 0; i < n; i++ {
			go func() {
				defer wg.Done()
				_ = d.Fetch(false)
				completed.Add(1)
			}()
		}
		<-entered // wait until the winning goroutine is blocked inside fetchCallback
		// All non-winning goroutines are blocked on once.Do; none should have completed yet.
		require.Equal(t, int32(0), completed.Load(), "no goroutine should complete while callback blocks")
		close(ready)
		wg.Wait()

		require.Equal(t, int32(1), callCount.Load())
		require.Equal(t, int32(n), completed.Load())
	})

	t.Run("all-waiters-get-same-error", func(t *testing.T) {
		ready := make(chan struct{})
		entered := make(chan struct{})

		d := &Dynamic{
			TemplatePath: "test.yaml",
			Variables:    []KV{{Key: "k", Value: "v"}},
		}
		require.NoError(t, d.Validate())
		d.fetchCallback = func(_ *Dynamic) error {
			close(entered)
			<-ready
			return nil
		}

		errs := make([]error, 20)
		var wg sync.WaitGroup
		wg.Add(len(errs))
		for i := range errs {
			i := i
			go func() {
				defer wg.Done()
				errs[i] = d.Fetch(false)
			}()
		}
		<-entered
		close(ready)
		wg.Wait()

		for _, err := range errs {
			require.NoError(t, err)
		}
	})

	t.Run("all-waiters-get-same-non-nil-error", func(t *testing.T) {
		ready := make(chan struct{})
		entered := make(chan struct{})
		sentinel := errkit.New("fetch failed")

		d := &Dynamic{
			TemplatePath: "test.yaml",
			Variables:    []KV{{Key: "k", Value: "v"}},
		}
		require.NoError(t, d.Validate())
		d.fetchCallback = func(_ *Dynamic) error {
			close(entered)
			<-ready
			return sentinel
		}

		errs := make([]error, 20)
		var wg sync.WaitGroup
		wg.Add(len(errs))
		for i := range errs {
			i := i
			go func() {
				defer wg.Done()
				errs[i] = d.Fetch(false)
			}()
		}
		<-entered
		close(ready)
		wg.Wait()

		for _, err := range errs {
			require.ErrorIs(t, err, sentinel)
		}
	})

	t.Run("unvalidated-returns-ErrNotValidated", func(t *testing.T) {
		d := &Dynamic{}
		err := d.Fetch(false)
		require.ErrorIs(t, err, ErrNotValidated)
	})

	t.Run("error-returns-ErrNotValidated-before-validate", func(t *testing.T) {
		d := &Dynamic{}
		require.ErrorIs(t, d.Error(), ErrNotValidated)
	})

	t.Run("shared-state-across-value-copies", func(t *testing.T) {
		var callCount atomic.Int32

		d := &Dynamic{
			TemplatePath: "test.yaml",
			Variables:    []KV{{Key: "k", Value: "v"}},
		}
		require.NoError(t, d.Validate())
		d.fetchCallback = func(_ *Dynamic) error {
			callCount.Add(1)
			return nil
		}

		// simulate what file.go does: embed Dynamic by value into DynamicAuthStrategy
		s1 := &DynamicAuthStrategy{Dynamic: *d}
		s2 := &DynamicAuthStrategy{Dynamic: *d}

		require.NoError(t, s1.Dynamic.Fetch(false))
		require.NoError(t, s2.Dynamic.Fetch(false))

		// fetchCallback must have run exactly once across both copies
		require.Equal(t, int32(1), callCount.Load())
	})
}
