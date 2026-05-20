package authx

import (
	"errors"
	"net/http"
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

func TestDynamicValidate(t *testing.T) {
	t.Run("missing template path", func(t *testing.T) {
		d := &Dynamic{
			Variables: []KV{{Key: "user", Value: "admin"}},
		}
		err := d.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "template-path is required")
	})

	t.Run("missing variables", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
		}
		err := d.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "variables are required")
	})

	t.Run("valid minimal dynamic", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		err := d.Validate()
		require.NoError(t, err)
		require.NotNil(t, d.fetchState, "fetchState should be initialized after Validate")
	})

	t.Run("valid with inline secret", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{{Key: "X-Token", Value: "{{token}}"}},
			},
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		err := d.Validate()
		require.NoError(t, err)
	})

	t.Run("valid with secrets array", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
			Secrets: []*Secret{
				{
					Type:    "Header",
					Domains: []string{"api.example.com"},
					Headers: []KV{{Key: "Authorization", Value: "Bearer {{token}}"}},
				},
			},
		}
		err := d.Validate()
		require.NoError(t, err)
	})

	t.Run("invalid inline secret propagates error", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type: "InvalidType",
			},
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		err := d.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid type")
	})

	t.Run("invalid secret in array propagates error", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
			Secrets: []*Secret{
				{
					Type: "Header",
					// missing domains — should fail
				},
			},
		}
		err := d.Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), "domains")
	})

	t.Run("re-validate resets fetch state", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		require.NoError(t, d.Validate())
		firstState := d.fetchState

		require.NoError(t, d.Validate())
		require.NotSame(t, firstState, d.fetchState, "fetchState should be a new instance after re-validate")
	})
}

func TestApplyValuesToSecret(t *testing.T) {
	t.Run("replaces header values", func(t *testing.T) {
		d := &Dynamic{
			Extracted: map[string]interface{}{"token": "secret-123"},
		}
		secret := &Secret{
			Headers: []KV{
				{Key: "Authorization", Value: "Bearer {{token}}"},
				{Key: "X-Static", Value: "no-template"},
			},
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "Bearer secret-123", secret.Headers[0].Value)
		require.Equal(t, "no-template", secret.Headers[1].Value)
	})

	t.Run("replaces header keys", func(t *testing.T) {
		d := &Dynamic{
			Extracted: map[string]interface{}{"hname": "X-Custom"},
		}
		secret := &Secret{
			Headers: []KV{
				{Key: "{{hname}}", Value: "value"},
			},
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "X-Custom", secret.Headers[0].Key)
	})

	t.Run("replaces cookie key and value", func(t *testing.T) {
		d := &Dynamic{
			Extracted: map[string]interface{}{"sid": "abc-xyz", "cname": "session"},
		}
		secret := &Secret{
			Cookies: []Cookie{
				{Key: "{{cname}}", Value: "{{sid}}"},
			},
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "session", secret.Cookies[0].Key)
		require.Equal(t, "abc-xyz", secret.Cookies[0].Value)
	})

	t.Run("replaces cookie raw", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "test.yaml",
			Extracted:    map[string]interface{}{"sid": "abc-xyz"},
		}
		secret := &Secret{
			Cookies: []Cookie{
				{Raw: "Set-Cookie: session={{sid}}; Path=/"},
			},
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "session", secret.Cookies[0].Key)
		require.Equal(t, "abc-xyz", secret.Cookies[0].Value)
	})

	t.Run("replaces query params", func(t *testing.T) {
		d := &Dynamic{
			Extracted: map[string]interface{}{"apikey": "key-42"},
		}
		secret := &Secret{
			Params: []KV{
				{Key: "api_key", Value: "{{apikey}}"},
			},
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "key-42", secret.Params[0].Value)
	})

	t.Run("replaces query param keys", func(t *testing.T) {
		d := &Dynamic{
			Extracted: map[string]interface{}{"pname": "token"},
		}
		secret := &Secret{
			Params: []KV{
				{Key: "{{pname}}", Value: "val"},
			},
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "token", secret.Params[0].Key)
	})

	t.Run("replaces username password token", func(t *testing.T) {
		d := &Dynamic{
			Extracted: map[string]interface{}{
				"user": "admin",
				"pass": "s3cret",
				"tok":  "jwt-abc",
			},
		}
		secret := &Secret{
			Username: "{{user}}",
			Password: "{{pass}}",
			Token:    "{{tok}}",
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "admin", secret.Username)
		require.Equal(t, "s3cret", secret.Password)
		require.Equal(t, "jwt-abc", secret.Token)
	})

	t.Run("leaves static values untouched", func(t *testing.T) {
		d := &Dynamic{
			Extracted: map[string]interface{}{"token": "xyz"},
		}
		secret := &Secret{
			Username: "fixed-user",
			Password: "fixed-pass",
			Token:    "fixed-token",
			Headers:  []KV{{Key: "X-Static", Value: "static-val"}},
			Params:   []KV{{Key: "q", Value: "search"}},
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "fixed-user", secret.Username)
		require.Equal(t, "fixed-pass", secret.Password)
		require.Equal(t, "fixed-token", secret.Token)
		require.Equal(t, "static-val", secret.Headers[0].Value)
		require.Equal(t, "search", secret.Params[0].Value)
	})

	t.Run("multiple extracted values in same template", func(t *testing.T) {
		d := &Dynamic{
			Extracted: map[string]interface{}{"user": "admin", "role": "superuser"},
		}
		secret := &Secret{
			Headers: []KV{
				{Key: "X-User", Value: "{{user}}"},
				{Key: "X-Role", Value: "{{role}}"},
			},
		}
		err := d.applyValuesToSecret(secret)
		require.NoError(t, err)
		require.Equal(t, "admin", secret.Headers[0].Value)
		require.Equal(t, "superuser", secret.Headers[1].Value)
	})

	t.Run("invalid raw cookie returns error", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "test.yaml",
			Extracted:    map[string]interface{}{},
		}
		secret := &Secret{
			Cookies: []Cookie{
				{Raw: "garbage-no-equals"},
			},
		}
		err := d.applyValuesToSecret(secret)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid raw cookie")
	})
}

func TestFetchWithoutValidate(t *testing.T) {
	d := &Dynamic{
		TemplatePath: "auth.yaml",
		Variables:    []KV{{Key: "user", Value: "admin"}},
	}
	err := d.Fetch(false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "Validate()")
}

func TestFetchWithoutCallback(t *testing.T) {
	d := &Dynamic{
		TemplatePath: "auth.yaml",
		Variables:    []KV{{Key: "user", Value: "admin"}},
	}
	require.NoError(t, d.Validate())
	err := d.Fetch(false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "SetLazyFetchCallback()")
}

func TestSetLazyFetchCallbackAppliesValues(t *testing.T) {
	t.Run("applies to inline secret", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{{Key: "Authorization", Value: "Bearer {{token}}"}},
			},
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
			dynamic.Extracted = map[string]interface{}{"token": "jwt-secret-123"}
			return nil
		})

		err := d.Fetch(false)
		require.NoError(t, err)
		require.Equal(t, "Bearer jwt-secret-123", d.Secret.Headers[0].Value)
	})

	t.Run("applies to secrets array", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
			Secrets: []*Secret{
				{
					Type:    "Header",
					Domains: []string{"api.example.com"},
					Headers: []KV{{Key: "X-Token", Value: "{{tok}}"}},
				},
				{
					Type:    "Query",
					Domains: []string{"other.com"},
					Params:  []KV{{Key: "key", Value: "{{apikey}}"}},
				},
			},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
			dynamic.Extracted = map[string]interface{}{"tok": "t-123", "apikey": "k-456"}
			return nil
		})

		err := d.Fetch(false)
		require.NoError(t, err)
		require.Equal(t, "t-123", d.Secrets[0].Headers[0].Value)
		require.Equal(t, "k-456", d.Secrets[1].Params[0].Value)
	})

	t.Run("callback error propagates", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(_ *Dynamic) error {
			return errors.New("auth server unreachable")
		})

		err := d.Fetch(false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "auth server unreachable")
	})

	t.Run("empty extracted returns error", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
			dynamic.Extracted = map[string]interface{}{}
			return nil
		})

		err := d.Fetch(false)
		require.Error(t, err)
		require.Contains(t, err.Error(), "no extracted values")
	})
}

func TestGetStrategies(t *testing.T) {
	t.Run("returns nil after failed fetch", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{{Key: "X-Token", Value: "{{token}}"}},
			},
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(_ *Dynamic) error {
			return errors.New("fetch failed")
		})

		strategies := d.GetStrategies()
		require.Nil(t, strategies)
	})

	t.Run("returns strategies after successful fetch with inline secret", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Type:    "Header",
				Domains: []string{"example.com"},
				Headers: []KV{{Key: "X-Token", Value: "{{token}}"}},
			},
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
			dynamic.Extracted = map[string]interface{}{"token": "abc"}
			return nil
		})

		strategies := d.GetStrategies()
		require.Len(t, strategies, 1)

		req, _ := http.NewRequest("GET", "https://example.com", nil)
		strategies[0].Apply(req)
		require.Equal(t, "abc", req.Header.Get("X-Token"))
	})

	t.Run("returns strategies for secrets array", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
			Secrets: []*Secret{
				{
					Type:    "Header",
					Domains: []string{"a.com"},
					Headers: []KV{{Key: "X-A", Value: "{{va}}"}},
				},
				{
					Type:    "Header",
					Domains: []string{"b.com"},
					Headers: []KV{{Key: "X-B", Value: "{{vb}}"}},
				},
			},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
			dynamic.Extracted = map[string]interface{}{"va": "val-a", "vb": "val-b"}
			return nil
		})

		strategies := d.GetStrategies()
		require.Len(t, strategies, 2)
	})

	t.Run("returns nil without validate", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		strategies := d.GetStrategies()
		require.Nil(t, strategies)
	})
}

func TestDynamicError(t *testing.T) {
	t.Run("nil before validate", func(t *testing.T) {
		d := &Dynamic{}
		require.Nil(t, d.Error())
	})

	t.Run("nil after successful fetch", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(dynamic *Dynamic) error {
			dynamic.Extracted = map[string]interface{}{"token": "abc"}
			return nil
		})
		_ = d.Fetch(false)
		require.Nil(t, d.Error())
	})

	t.Run("non-nil after failed fetch", func(t *testing.T) {
		d := &Dynamic{
			TemplatePath: "auth.yaml",
			Variables:    []KV{{Key: "user", Value: "admin"}},
		}
		require.NoError(t, d.Validate())
		d.SetLazyFetchCallback(func(_ *Dynamic) error {
			return errors.New("boom")
		})
		_ = d.Fetch(false)
		require.Error(t, d.Error())
		require.Contains(t, d.Error().Error(), "boom")
	})
}

func TestGetDomainAndDomainRegex(t *testing.T) {
	t.Run("inline secret only", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Domains:      []string{"a.com"},
				DomainsRegex: []string{".*\\.a\\.com"},
			},
		}
		domains, regexes := d.GetDomainAndDomainRegex()
		require.Equal(t, []string{"a.com"}, domains)
		require.Equal(t, []string{".*\\.a\\.com"}, regexes)
	})

	t.Run("secrets array only", func(t *testing.T) {
		d := &Dynamic{
			Secrets: []*Secret{
				{Domains: []string{"b.com"}, DomainsRegex: []string{".*\\.b\\.com"}},
				{Domains: []string{"c.com"}},
			},
		}
		domains, regexes := d.GetDomainAndDomainRegex()
		require.ElementsMatch(t, []string{"b.com", "c.com"}, domains)
		require.Equal(t, []string{".*\\.b\\.com"}, regexes)
	})

	t.Run("deduplicates", func(t *testing.T) {
		d := &Dynamic{
			Secret: &Secret{
				Domains: []string{"a.com"},
			},
			Secrets: []*Secret{
				{Domains: []string{"a.com", "b.com"}},
			},
		}
		domains, _ := d.GetDomainAndDomainRegex()
		require.ElementsMatch(t, []string{"a.com", "b.com"}, domains)
	})

	t.Run("no secret returns nil", func(t *testing.T) {
		d := &Dynamic{}
		domains, regexes := d.GetDomainAndDomainRegex()
		require.Nil(t, domains)
		require.Nil(t, regexes)
	})
}
