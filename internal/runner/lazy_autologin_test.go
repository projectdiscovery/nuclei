package runner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

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
