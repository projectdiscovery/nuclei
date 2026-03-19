package authx

import (
	"errors"
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

func newTestDynamic(t *testing.T, callback LazyFetchSecret) *Dynamic {
	t.Helper()

	dynamic := &Dynamic{
		Secret: &Secret{
			Type:    string(BearerTokenAuth),
			Domains: []string{"example.com"},
			Token:   "Bearer {{token}}",
		},
		TemplatePath: "auth-template.yaml",
		Variables: []KV{{
			Key:   "username",
			Value: "tester",
		}},
	}
	require.NoError(t, dynamic.Validate())
	dynamic.SetLazyFetchCallback(callback)
	return dynamic
}

func TestDynamicFetchBlocksConcurrentCallers(t *testing.T) {
	var calls atomic.Int32
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 2)

	dynamic := newTestDynamic(t, func(d *Dynamic) error {
		calls.Add(1)
		close(started)
		<-release
		d.Extracted = map[string]interface{}{"token": "secret-token"}
		return nil
	})

	go func() {
		done <- dynamic.Fetch(false)
	}()

	<-started

	go func() {
		done <- dynamic.Fetch(false)
	}()

	select {
	case err := <-done:
		t.Fatalf("concurrent fetch returned before first fetch finished: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	require.NoError(t, <-done)
	require.NoError(t, <-done)
	require.EqualValues(t, 1, calls.Load())
	require.True(t, dynamic.fetched.Load())
	require.Equal(t, "Bearer secret-token", dynamic.Secret.Token)
}

func TestDynamicGetStrategiesWaitsForFetchCompletion(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan []AuthStrategy, 1)

	dynamic := newTestDynamic(t, func(d *Dynamic) error {
		close(started)
		<-release
		d.Extracted = map[string]interface{}{"token": "secret-token"}
		return nil
	})

	go func() {
		done <- dynamic.GetStrategies()
	}()

	<-started

	select {
	case strategies := <-done:
		t.Fatalf("strategies became available before fetch completed: %d", len(strategies))
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	strategies := <-done
	require.Len(t, strategies, 1)
	require.Equal(t, "Bearer secret-token", dynamic.Secret.Token)
	require.NoError(t, dynamic.Error())
}

func TestDynamicGetStrategiesReturnsNilOnFetchFailure(t *testing.T) {
	expectedErr := errors.New("fetch failed")
	dynamic := newTestDynamic(t, func(d *Dynamic) error {
		return expectedErr
	})

	require.ErrorIs(t, dynamic.Fetch(false), expectedErr)
	require.Nil(t, dynamic.GetStrategies())
	require.ErrorIs(t, dynamic.Error(), expectedErr)
	require.True(t, dynamic.fetched.Load())
}
