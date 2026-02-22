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

func TestDynamicFetchConcurrentWaitsForCompletion(t *testing.T) {
	d := &Dynamic{
		Secret: &Secret{
			Type:    string(BearerTokenAuth),
			Domains: []string{"example.com"},
			Token:   "{{token}}",
		},
		TemplatePath: "dynamic-auth-template.yaml",
		Variables: []KV{
			{Key: "username", Value: "alice"},
		},
		fetched:  &atomic.Bool{},
		fetching: &atomic.Bool{},
	}

	d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
		time.Sleep(120 * time.Millisecond)
		dynamic.Extracted = map[string]interface{}{"token": "resolved-token"}
		return nil
	})

	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([][]AuthStrategy, 2)
	durations := make([]time.Duration, 2)

	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			begin := time.Now()
			results[i] = d.GetStrategies()
			durations[i] = time.Since(begin)
		}(i)
	}

	close(start)
	wg.Wait()

	for i := range results {
		require.Len(t, results[i], 1)
		bearer, ok := results[i][0].(*BearerTokenAuthStrategy)
		require.True(t, ok)
		require.Equal(t, "resolved-token", bearer.Data.Token)
	}
	for i := range durations {
		require.GreaterOrEqual(t, durations[i], 100*time.Millisecond)
	}
}

func TestDynamicFetchRecoverPanics(t *testing.T) {
	d := &Dynamic{
		Secret: &Secret{
			Type:    string(BearerTokenAuth),
			Domains: []string{"example.com"},
			Token:   "{{token}}",
		},
		TemplatePath: "dynamic-auth-template.yaml",
		Variables: []KV{
			{Key: "username", Value: "alice"},
		},
		fetched:  &atomic.Bool{},
		fetching: &atomic.Bool{},
	}

	d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
		panic("panic while fetching token")
	})

	err := d.Fetch(false)
	require.ErrorContains(t, err, "fetch callback panicked")
}

func TestDynamicFetchTimeoutDoesNotHangConcurrentWaiters(t *testing.T) {
	previousTimeout := dynamicFetchTimeout
	dynamicFetchTimeout = 100 * time.Millisecond
	defer func() {
		dynamicFetchTimeout = previousTimeout
	}()

	d := &Dynamic{
		Secret: &Secret{
			Type:    string(BearerTokenAuth),
			Domains: []string{"example.com"},
			Token:   "{{token}}",
		},
		TemplatePath: "dynamic-auth-template.yaml",
		Variables: []KV{
			{Key: "username", Value: "alice"},
		},
		fetched:  &atomic.Bool{},
		fetching: &atomic.Bool{},
	}

	d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
		time.Sleep(5 * time.Second)
		dynamic.Extracted = map[string]interface{}{"token": "resolved-token"}
		return nil
	})

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	durations := make([]time.Duration, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			begin := time.Now()
			errs[i] = d.Fetch(false)
			durations[i] = time.Since(begin)
		}(i)
	}

	close(start)
	wg.Wait()

	for _, err := range errs {
		require.ErrorContains(t, err, "timeout waiting for fetch callback")
	}
	for _, duration := range durations {
		require.LessOrEqual(t, duration, 500*time.Millisecond)
		require.Greater(t, duration, 90*time.Millisecond)
	}
}
