package runner

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/autologin"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCaptureSessionToStore(t *testing.T) {
	session := &autologin.Session{
		Cookies:        []*http.Cookie{{Name: "session", Value: "sess-dave"}},
		Token:          "eyJ.payload.sig",
		LocalStorage:   map[string]string{"jwt": "eyJ.payload.sig"},
		SessionStorage: map[string]string{"csrf": "tok"},
	}
	store, err := captureSessionToStore(session, "app.example.com")
	require.NoError(t, err)
	require.Len(t, store.Secrets, 3, "cookies, token and web storage must each map to a secret")

	byType := map[string]authx.Secret{}
	for _, s := range store.Secrets {
		byType[s.Type] = s
		require.Equal(t, []string{"app.example.com"}, s.Domains, "every secret is scoped to the login host")
		require.NoError(t, s.Validate())
	}

	require.Equal(t, "session", byType[string(authx.CookiesAuth)].Cookies[0].Key)
	require.Equal(t, "eyJ.payload.sig", byType[string(authx.BearerTokenAuth)].Token)

	ws := byType[string(authx.WebStorageAuth)]
	require.Equal(t, "eyJ.payload.sig", ws.LocalStorage["jwt"])
	require.Equal(t, "tok", ws.SessionStorage["csrf"])

	// The web storage secret must surface as a BrowserStorageProvider so the
	// headless engine can seed it into scanned pages.
	bsp, ok := ws.GetStrategy().(authx.BrowserStorageProvider)
	require.True(t, ok)
	local, sess := bsp.WebStorage()
	require.Equal(t, "eyJ.payload.sig", local["jwt"])
	require.Equal(t, "tok", sess["csrf"])
}

func TestCaptureSessionToStore_StorageOnly(t *testing.T) {
	// A pure token-in-localStorage SPA: no cookies, no extracted token, only
	// web storage — it must still produce a usable store.
	session := &autologin.Session{LocalStorage: map[string]string{"jwt": "x"}}
	store, err := captureSessionToStore(session, "spa.example.com")
	require.NoError(t, err)
	require.Len(t, store.Secrets, 1)
	require.Equal(t, string(authx.WebStorageAuth), store.Secrets[0].Type)
}

func TestCaptureSessionToStore_Empty(t *testing.T) {
	_, err := captureSessionToStore(&autologin.Session{}, "app.example.com")
	require.Error(t, err, "an empty session must not produce a store")
}

func TestAutoLoginStoreFromOptions_RecordingDerivesHost(t *testing.T) {
	recording := `{"steps": [
		{"type": "navigate", "url": "https://recorded.example.com/signin"},
		{"type": "change", "value": "bob", "selectors": [["#user"]]}
	]}`
	path := filepath.Join(t.TempDir(), "flow.json")
	require.NoError(t, os.WriteFile(path, []byte(recording), 0o600))

	// No -auth-login-url: the host scope must come from the recording.
	opts := &types.Options{AuthRecording: path, AuthUsername: "bob", AuthPassword: "p"}
	store, err := autoLoginStoreFromOptions(opts)
	require.NoError(t, err)
	require.Len(t, store.Dynamic, 1)
	require.Equal(t, []string{"recorded.example.com"}, store.Dynamic[0].Secret.Domains)
	require.Equal(t, path, store.Dynamic[0].AutoLogin.Recording)
}

func TestAutoLoginStoreFromOptions(t *testing.T) {
	opts := &types.Options{
		AuthLoginURL:      "https://app.example.com:8443/login",
		AuthUsername:      "alice",
		AuthPassword:      "s3cr3t",
		AuthUsernameField: "email",
		AuthHeadless:      true,
	}
	store, err := autoLoginStoreFromOptions(opts)
	require.NoError(t, err)
	require.Len(t, store.Dynamic, 1)

	dyn := store.Dynamic[0]
	require.NotNil(t, dyn.Secret)
	require.Equal(t, []string{"app.example.com:8443"}, dyn.Secret.Domains, "session should be scoped to the login host")
	require.NotNil(t, dyn.AutoLogin)
	require.Equal(t, "https://app.example.com:8443/login", dyn.AutoLogin.LoginURL)
	require.Equal(t, "alice", dyn.AutoLogin.Username)
	require.Equal(t, "email", dyn.AutoLogin.UsernameField)
	require.True(t, dyn.AutoLogin.Headless)

	// The assembled store must validate as a real auto-login dynamic.
	require.NoError(t, dyn.Validate())
}

func TestAutoLoginStoreFromOptions_InvalidURL(t *testing.T) {
	_, err := autoLoginStoreFromOptions(&types.Options{AuthLoginURL: "://nohost"})
	require.Error(t, err)
}

func TestAutoLoginStoreFromOptions_SessionLifecycle(t *testing.T) {
	opts := &types.Options{
		AuthLoginURL:          "https://app.example.com/login",
		AuthUsername:          "alice",
		AuthPassword:          "s3cr3t",
		AuthReauthStatusCodes: "401, 403",
		AuthRefreshInterval:   "15m",
	}
	store, err := autoLoginStoreFromOptions(opts)
	require.NoError(t, err)
	dyn := store.Dynamic[0]
	require.Equal(t, []int{401, 403}, dyn.ReauthStatusCodes, "reauth status codes must be threaded onto the dynamic")
	require.Equal(t, "15m", dyn.RefreshInterval)
	// The lifecycle-configured store must validate (refresh-interval is parsed).
	require.NoError(t, dyn.Validate())
}

func TestAutoLoginStoreFromOptions_InvalidReauthCodes(t *testing.T) {
	_, err := autoLoginStoreFromOptions(&types.Options{
		AuthLoginURL:          "https://app.example.com/login",
		AuthPassword:          "s3cr3t",
		AuthReauthStatusCodes: "401,nope",
	})
	require.Error(t, err, "non-numeric reauth status code must be rejected")
}

func TestParseStatusCodes(t *testing.T) {
	cases := []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"", nil, false},
		{"   ", nil, false},
		{"401", []int{401}, false},
		{"401,403, 419", []int{401, 403, 419}, false},
		{"401,,403", []int{401, 403}, false},
		{"abc", nil, true},
		{"99", nil, true},
		{"600", nil, true},
	}
	for _, tc := range cases {
		got, err := parseStatusCodes(tc.in)
		if tc.wantErr {
			require.Error(t, err, "input %q", tc.in)
			continue
		}
		require.NoError(t, err, "input %q", tc.in)
		require.Equal(t, tc.want, got, "input %q", tc.in)
	}
}

func TestBuildAutoLoginRuntimeOptions(t *testing.T) {
	opts := &types.Options{
		CustomHeaders:      []string{"User-Agent: NucleiScan/1.0", "X-Env: staging", "malformed-header"},
		AliveHttpProxy:     "http://127.0.0.1:8080",
		CDPEndpoint:        "ws://127.0.0.1:9222",
		UseInstalledChrome: true,
		ShowBrowser:        true,
	}
	rt := buildAutoLoginRuntimeOptions(opts)
	require.Equal(t, "NucleiScan/1.0", rt.UserAgent, "User-Agent should be split out of custom headers")
	require.Equal(t, "staging", rt.CustomHeaders["X-Env"])
	require.NotContains(t, rt.CustomHeaders, "User-Agent", "UA must not be duplicated into custom headers")
	require.Equal(t, "http://127.0.0.1:8080", rt.Proxy)
	require.Equal(t, "ws://127.0.0.1:9222", rt.CDPEndpoint)
	require.True(t, rt.UseInstalledChrome)
	require.True(t, rt.ShowBrowser)
}

func TestBuildAutoLoginRuntimeOptions_SocksProxyFallback(t *testing.T) {
	// With only a SOCKS proxy configured, the auto-login must still pick it up
	// (regression: previously only AliveHttpProxy was threaded).
	rt := buildAutoLoginRuntimeOptions(&types.Options{
		AliveSocksProxy: "socks5://127.0.0.1:1080",
	})
	require.Equal(t, "socks5://127.0.0.1:1080", rt.Proxy)

	// HTTP proxy takes precedence when both are set.
	rt = buildAutoLoginRuntimeOptions(&types.Options{
		AliveHttpProxy:  "http://127.0.0.1:8080",
		AliveSocksProxy: "socks5://127.0.0.1:1080",
	})
	require.Equal(t, "http://127.0.0.1:8080", rt.Proxy)
}
