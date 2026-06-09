package authx

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/autologin"
	"github.com/stretchr/testify/require"
)

func TestAutoLoginConfig_Validate_Recording(t *testing.T) {
	recording := `{"steps": [
		{"type": "navigate", "url": "https://app.example.com/login"},
		{"type": "change", "value": "dave", "selectors": [["#user"]]},
		{"type": "change", "value": "secret", "selectors": [["#pass"]]},
		{"type": "click", "selectors": [["#submit"]]}
	]}`
	path := filepath.Join(t.TempDir(), "login.flow.json")
	require.NoError(t, os.WriteFile(path, []byte(recording), 0o600))

	// LoginURL intentionally omitted: it must be derived from the recording.
	cfg := &AutoLoginConfig{Recording: path, Username: "dave", Password: "secret"}
	require.NoError(t, cfg.Validate())

	require.True(t, cfg.Headless, "a recording must force a headless login")
	require.Equal(t, "https://app.example.com/login", cfg.LoginURL, "login URL derived from first navigate step")
	require.Equal(t, []autologin.LoginStep{
		{Action: "navigate", Value: "https://app.example.com/login"},
		{Action: "fill", Selector: "#user", Value: "{{username}}"},
		{Action: "fill", Selector: "#pass", Value: "{{password}}"},
		{Action: "click", Selector: "#submit"},
	}, cfg.Steps, "recording must compile to placeholder-parameterized steps")
}

func TestAutoLoginConfig_Validate_RecordingMissingFile(t *testing.T) {
	cfg := &AutoLoginConfig{Recording: filepath.Join(t.TempDir(), "nope.json"), Password: "x"}
	require.Error(t, cfg.Validate(), "a missing recording file must fail validation")
}

func newAutoLoginDynamic() *Dynamic {
	return &Dynamic{
		Secret:    &Secret{Domains: []string{"app.example.com"}},
		AutoLogin: &AutoLoginConfig{LoginURL: "https://app.example.com/login", Password: "x"},
	}
}

func TestApplyAutoLoginSession_CookiesOnly(t *testing.T) {
	d := newAutoLoginDynamic()
	err := d.applyAutoLoginSession(&autologin.Session{
		Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
	})
	require.NoError(t, err)
	require.Equal(t, string(CookiesAuth), d.Secret.Type)
	require.Len(t, d.Secret.Cookies, 1)
	require.Equal(t, "session", d.Secret.Cookies[0].Key)
	require.Empty(t, d.Secrets, "no extra bearer secret when there is no token")
}

func TestApplyAutoLoginSession_TokenOnly(t *testing.T) {
	d := newAutoLoginDynamic()
	err := d.applyAutoLoginSession(&autologin.Session{Token: "jwt-123"})
	require.NoError(t, err)
	require.Equal(t, string(BearerTokenAuth), d.Secret.Type)
	require.Equal(t, "jwt-123", d.Secret.Token)
	require.Empty(t, d.Secrets)
}

func TestApplyAutoLoginSession_CookiesAndToken(t *testing.T) {
	d := newAutoLoginDynamic()
	require.NoError(t, d.Validate())
	err := d.applyAutoLoginSession(&autologin.Session{
		Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
		Token:   "jwt-123",
	})
	require.NoError(t, err)
	require.Equal(t, string(CookiesAuth), d.Secret.Type)
	// The bearer lives on the shared fetchState (so it reaches every scoped
	// domain), not on the per-copy Secrets slice.
	require.Empty(t, d.Secrets, "bearer must not live on the per-copy Secrets slice")
	require.Len(t, d.fetchState.autoLoginSecrets, 1, "token should be applied as an additional bearer secret")
	require.Equal(t, string(BearerTokenAuth), d.fetchState.autoLoginSecrets[0].Type)
	require.Equal(t, "jwt-123", d.fetchState.autoLoginSecrets[0].Token)
	require.Equal(t, []string{"app.example.com"}, d.fetchState.autoLoginSecrets[0].Domains)
}

func TestApplyAutoLoginSession_Empty(t *testing.T) {
	d := newAutoLoginDynamic()
	err := d.applyAutoLoginSession(&autologin.Session{})
	require.Error(t, err)
}

func TestSummarizeSession(t *testing.T) {
	require.Equal(t, "no session", summarizeSession(nil))
	require.Equal(t, "no usable session material", summarizeSession(&autologin.Session{}))
	require.Equal(t, "2 cookie(s)", summarizeSession(&autologin.Session{
		Cookies: []*http.Cookie{{Name: "a"}, {Name: "b"}},
	}))
	require.Equal(t, "1 cookie(s), bearer token, 2 localStorage item(s)", summarizeSession(&autologin.Session{
		Cookies:      []*http.Cookie{{Name: "a"}},
		Token:        "jwt",
		LocalStorage: map[string]string{"x": "1", "y": "2"},
	}))
}

func TestAutoLoginEngineName(t *testing.T) {
	require.Equal(t, "headless", autoLoginEngineName(true))
	require.Equal(t, "http", autoLoginEngineName(false))
}

// TestDynamic_WebStorage_ConcurrentReauth exercises the locking contract that
// storage replay relies on: readers (the headless engine) call WebStorage while
// re-authentication concurrently rewrites the captured storage on the shared
// fetchState. Must be run under -race.
func TestDynamic_WebStorage_ConcurrentReauth(t *testing.T) {
	d := newAutoLoginDynamic()
	d.ReauthStatusCodes = []int{401}
	require.NoError(t, d.Validate())

	var gen atomic.Int64
	// Each (re)auth captures a fresh storage map, simulating a new session.
	d.fetchCallback = func(dyn *Dynamic) error {
		n := gen.Add(1)
		// Cookie + token + storage so every shared-state write path (Secret,
		// fetchState.autoLoginSecrets, webStorage) is exercised under -race.
		return dyn.applyAutoLoginSession(&autologin.Session{
			Cookies:      []*http.Cookie{{Name: "session", Value: fmt.Sprintf("v%d", n)}},
			Token:        fmt.Sprintf("token-%d", n),
			LocalStorage: map[string]string{"jwt": fmt.Sprintf("token-%d", n)},
		})
	}

	// Share the session across value-copies, as the real provider does.
	strategy := &DynamicAuthStrategy{Dynamic: *d}

	var wg sync.WaitGroup
	const workers = 8
	const iterations = 200
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				switch id % 4 {
				case 0:
					// Force a re-auth (rewrites the storage map under the write lock).
					strategy.Dynamic.MarkStale()
					_ = strategy.Dynamic.Fetch(false)
				case 1:
					// Read + iterate storage the way resolveBrowserStorage does.
					local, session := strategy.WebStorage()
					for k, v := range local {
						_ = k + v
					}
					for k, v := range session {
						_ = k + v
					}
					// Also materialize strategies (reads shared autoLoginSecrets).
					_ = strategy.Dynamic.GetStrategies()
				case 2:
					strategy.Dynamic.ApplyStrategies(func(AuthStrategy) {})
				default:
					_ = strategy.Dynamic.NotifyResponse(401)
				}
			}
		}(w)
	}
	wg.Wait()

	// After the storm, a fresh fetch must still yield a consistent session.
	local, _ := strategy.WebStorage()
	require.NotEmpty(t, local["jwt"], "storage must remain populated after concurrent re-auth")
}

// TestAutoLogin_MultiDomain_BearerSharedAcrossCopies reproduces a sharing bug:
// the auto-login session (cookie + bearer token) must be applied on *every*
// domain the secret is scoped to, not just the one whose DynamicAuthStrategy
// copy happened to trigger the login. init() creates one value-copy per domain,
// all sharing *Secret and *fetchState; the extra bearer secret must be visible
// to sibling copies too.
func TestAutoLogin_MultiDomain_BearerSharedAcrossCopies(t *testing.T) {
	d := &Dynamic{
		Secret:    &Secret{Domains: []string{"app.example.com", "api.example.com"}},
		AutoLogin: &AutoLoginConfig{LoginURL: "https://app.example.com/login", Password: "x"},
	}
	require.NoError(t, d.Validate())
	d.fetchCallback = func(dyn *Dynamic) error {
		return dyn.applyAutoLoginSession(&autologin.Session{
			Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
			Token:   "jwt-123",
		})
	}

	// Mirror init(): one copy per domain, sharing the pointers.
	copyApp := &DynamicAuthStrategy{Dynamic: *d}
	copyAPI := &DynamicAuthStrategy{Dynamic: *d}

	// The app-domain copy triggers the login.
	appStrategies := copyApp.Dynamic.GetStrategies()
	require.Len(t, appStrategies, 2, "app domain must get cookie + bearer")

	// The api-domain copy (login already done, shared fetchState) must ALSO see
	// both the cookie and the bearer token.
	apiStrategies := copyAPI.Dynamic.GetStrategies()
	require.Len(t, apiStrategies, 2, "api domain must also get cookie + bearer (shared session)")

	// Concretely, the bearer must be applied to a request on the api domain.
	req, _ := http.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
	copyAPI.Apply(req)
	require.Equal(t, "Bearer jwt-123", req.Header.Get("Authorization"), "bearer token must reach the api domain")
	require.NotEmpty(t, req.Header.Get("Cookie"), "session cookie must reach the api domain")
}

func TestApplyAutoLoginSession_WebStorageCaptured(t *testing.T) {
	d := newAutoLoginDynamic()
	require.NoError(t, d.Validate())
	d.SetAutoLoginCallback(nil)
	// Stub the fetch to bypass the network and simulate a headless capture.
	d.fetchCallback = func(dyn *Dynamic) error {
		return dyn.applyAutoLoginSession(&autologin.Session{
			Cookies:        []*http.Cookie{{Name: "session", Value: "abc"}},
			LocalStorage:   map[string]string{"jwt": "eyJ..."},
			SessionStorage: map[string]string{"csrf": "tok"},
		})
	}

	local, session := d.WebStorage()
	require.Equal(t, map[string]string{"jwt": "eyJ..."}, local)
	require.Equal(t, map[string]string{"csrf": "tok"}, session)

	// And the DynamicAuthStrategy must surface the same storage to the engine.
	strat := &DynamicAuthStrategy{Dynamic: *d}
	l2, s2 := strat.WebStorage()
	require.Equal(t, "eyJ...", l2["jwt"])
	require.Equal(t, "tok", s2["csrf"])
}

func TestApplyAutoLoginSession_StorageOnly(t *testing.T) {
	d := newAutoLoginDynamic()
	require.NoError(t, d.Validate())
	// Storage-only session (pure localStorage-JWT SPA): no HTTP secret, but the
	// session is still valid because storage will be replayed by the engine.
	err := d.applyAutoLoginSession(&autologin.Session{
		LocalStorage: map[string]string{"jwt": "x"},
	})
	require.NoError(t, err)
	require.Empty(t, d.Secret.Type, "storage-only session yields no HTTP strategy")
	require.Equal(t, map[string]string{"jwt": "x"}, d.fetchState.webStorageLocal)
}

func TestApplyAutoLoginSession_ReauthReplaces(t *testing.T) {
	d := newAutoLoginDynamic()
	require.NoError(t, d.Validate())
	// First auth: cookies + token (creates an extra bearer secret).
	require.NoError(t, d.applyAutoLoginSession(&autologin.Session{
		Cookies: []*http.Cookie{{Name: "session", Value: "v1"}},
		Token:   "jwt-1",
	}))
	require.Len(t, d.fetchState.autoLoginSecrets, 1)

	// Re-auth: cookies only -> the previous bearer secret and cookies must be
	// fully replaced, not appended.
	require.NoError(t, d.applyAutoLoginSession(&autologin.Session{
		Cookies: []*http.Cookie{{Name: "session", Value: "v2"}},
	}))
	require.Empty(t, d.fetchState.autoLoginSecrets, "stale bearer secret must be cleared on re-auth")
	require.Len(t, d.Secret.Cookies, 1)
	require.Equal(t, "v2", d.Secret.Cookies[0].Value, "cookie value must be refreshed")
}
