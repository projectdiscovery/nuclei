package authx

import (
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// newDynamicWithToken builds a validated dynamic secret whose login callback
// returns an incrementing token each time it runs, so re-authentication is observable.
func newDynamicWithToken(t *testing.T, calls *atomic.Int32) *Dynamic {
	t.Helper()
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
	d.SetLazyFetchCallback(func(dyn *Dynamic) error {
		n := calls.Add(1)
		dyn.Extracted = map[string]interface{}{"token": tokenForCall(n)}
		return nil
	})
	return d
}

func tokenForCall(n int32) string {
	switch n {
	case 1:
		return "token-1"
	case 2:
		return "token-2"
	case 3:
		return "token-3"
	default:
		return "token-n"
	}
}

func applyHeader(t *testing.T, d *Dynamic) string {
	t.Helper()
	strategy := &DynamicAuthStrategy{Dynamic: *d}
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	strategy.Apply(req)
	return req.Header.Get("Authorization")
}

func TestSessionRefreshReRendersTemplate(t *testing.T) {
	var calls atomic.Int32
	d := newDynamicWithToken(t, &calls)

	require.Equal(t, "Bearer token-1", applyHeader(t, d), "first fetch should render initial token")
	require.Equal(t, "Bearer token-1", applyHeader(t, d), "second apply should reuse cached session")
	require.Equal(t, int32(1), calls.Load(), "login should run once before refresh")

	require.NoError(t, d.Refresh(false))
	require.Equal(t, int32(2), calls.Load(), "refresh should re-run the login flow")
	require.Equal(t, "Bearer token-2", applyHeader(t, d), "refresh must re-render template with the new token")
}

func TestSessionMarkStaleTriggersReauth(t *testing.T) {
	var calls atomic.Int32
	d := newDynamicWithToken(t, &calls)

	require.Equal(t, "Bearer token-1", applyHeader(t, d))
	require.Equal(t, int32(1), calls.Load())

	d.MarkStale()
	require.True(t, d.IsExpired(), "session should report expired after MarkStale")

	require.Equal(t, "Bearer token-2", applyHeader(t, d), "stale session should re-authenticate on next apply")
	require.Equal(t, int32(2), calls.Load())
	require.False(t, d.IsExpired(), "session should be fresh again after re-auth")
}

func TestSessionRefreshIntervalExpiry(t *testing.T) {
	var calls atomic.Int32
	d := &Dynamic{
		Secret: &Secret{
			Type:    "Header",
			Domains: []string{"example.com"},
			Headers: []KV{{Key: "Authorization", Value: "Bearer {{token}}"}},
		},
		TemplatePath:    "auth.yaml",
		Variables:       []KV{{Key: "user", Value: "admin"}},
		RefreshInterval: "40ms",
	}
	require.NoError(t, d.Validate())
	d.SetLazyFetchCallback(func(dyn *Dynamic) error {
		n := calls.Add(1)
		dyn.Extracted = map[string]interface{}{"token": tokenForCall(n)}
		return nil
	})

	require.Equal(t, "Bearer token-1", applyHeader(t, d))
	require.Equal(t, "Bearer token-1", applyHeader(t, d), "within interval the session is reused")
	require.Equal(t, int32(1), calls.Load())

	time.Sleep(60 * time.Millisecond)
	require.True(t, d.IsExpired(), "session should expire after the refresh interval")
	require.Equal(t, "Bearer token-2", applyHeader(t, d), "expired session should re-authenticate")
	require.Equal(t, int32(2), calls.Load())
}

func TestSessionNotifyResponseReauth(t *testing.T) {
	t.Run("configured status marks stale", func(t *testing.T) {
		var calls atomic.Int32
		d := newDynamicWithToken(t, &calls)
		d.ReauthStatusCodes = []int{401, 403}

		require.Equal(t, "Bearer token-1", applyHeader(t, d))

		require.False(t, d.NotifyResponse(200), "2xx must not trigger re-auth")
		require.False(t, d.IsExpired())

		require.True(t, d.NotifyResponse(401), "401 must trigger re-auth for established session")
		require.True(t, d.IsExpired())

		require.Equal(t, "Bearer token-2", applyHeader(t, d))
		require.Equal(t, int32(2), calls.Load())
	})

	t.Run("no reauth before first fetch", func(t *testing.T) {
		var calls atomic.Int32
		d := newDynamicWithToken(t, &calls)
		d.ReauthStatusCodes = []int{401}

		require.False(t, d.NotifyResponse(401), "should not mark stale before a session exists")
		require.Equal(t, int32(0), calls.Load())
	})

	t.Run("unconfigured status code is ignored", func(t *testing.T) {
		var calls atomic.Int32
		d := newDynamicWithToken(t, &calls)
		// ReauthStatusCodes left empty => response-triggered reauth disabled
		require.Equal(t, "Bearer token-1", applyHeader(t, d))
		require.False(t, d.NotifyResponse(401))
		require.False(t, d.IsExpired())
	})
}

func TestSessionResponseInspectorInterface(t *testing.T) {
	var calls atomic.Int32
	d := newDynamicWithToken(t, &calls)
	d.ReauthStatusCodes = []int{401}
	var strategy AuthStrategy = &DynamicAuthStrategy{Dynamic: *d}

	inspector, ok := strategy.(ResponseInspector)
	require.True(t, ok, "DynamicAuthStrategy must implement ResponseInspector")

	// establish session via the same shared state
	req, _ := http.NewRequest("GET", "https://example.com", nil)
	strategy.Apply(req)
	require.Equal(t, "Bearer token-1", req.Header.Get("Authorization"))

	require.True(t, inspector.OnResponse(401))
	req2, _ := http.NewRequest("GET", "https://example.com", nil)
	strategy.Apply(req2)
	require.Equal(t, "Bearer token-2", req2.Header.Get("Authorization"))
}

func TestSessionValidateRejectsBadRefreshInterval(t *testing.T) {
	d := &Dynamic{
		TemplatePath:    "auth.yaml",
		Variables:       []KV{{Key: "user", Value: "admin"}},
		RefreshInterval: "not-a-duration",
	}
	err := d.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid refresh-interval")
}

// TestSessionConcurrentApplyDuringReauth exercises the locking contract: request
// threads applying the strategy must never race a concurrent re-authentication.
// Intended to be run with -race.
func TestSessionConcurrentApplyDuringReauth(t *testing.T) {
	var calls atomic.Int32
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
	d.SetLazyFetchCallback(func(dyn *Dynamic) error {
		calls.Add(1)
		// simulate some work during login so writers and readers overlap
		time.Sleep(time.Millisecond)
		dyn.Extracted = map[string]interface{}{"token": "tok"}
		return nil
	})

	strategy := &DynamicAuthStrategy{Dynamic: *d}

	const workers = 16
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// readers continuously apply the strategy
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					req, _ := http.NewRequest("GET", "https://example.com", nil)
					strategy.Apply(req)
					require.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
				}
			}
		}()
	}

	// writers continuously invalidate the session, forcing re-auth
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					d.MarkStale()
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}

	time.Sleep(200 * time.Millisecond)
	close(stop)
	wg.Wait()

	require.Greater(t, calls.Load(), int32(1), "re-authentication should have happened multiple times")
}
