package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

// fakeStorageProvider is a minimal AuthProvider returning a fixed set of
// strategies for any URL, used to unit-test storage resolution without a browser.
type fakeStorageProvider struct {
	strategies []authx.AuthStrategy
}

func (f *fakeStorageProvider) LookupAddr(string) []authx.AuthStrategy       { return f.strategies }
func (f *fakeStorageProvider) LookupURL(*url.URL) []authx.AuthStrategy      { return f.strategies }
func (f *fakeStorageProvider) LookupURLX(*urlutil.URL) []authx.AuthStrategy { return f.strategies }
func (f *fakeStorageProvider) GetTemplatePaths() []string                   { return nil }
func (f *fakeStorageProvider) PreFetchSecrets() error                       { return nil }
func (f *fakeStorageProvider) Close()                                       {}

func TestResolveBrowserStorage(t *testing.T) {
	provider := &fakeStorageProvider{strategies: []authx.AuthStrategy{
		// A non-storage strategy must be ignored.
		authx.NewBearerTokenAuthStrategy(&authx.Secret{Type: "BearerToken", Token: "t"}),
		authx.NewWebStorageAuthStrategy(
			map[string]string{"jwt": "eyJ.payload.sig"},
			map[string]string{"csrf": "tok"},
		),
	}}
	target, _ := urlutil.Parse("https://app.example.com/dashboard")

	local, session := resolveBrowserStorage(provider, target)
	require.Equal(t, "eyJ.payload.sig", local["jwt"])
	require.Equal(t, "tok", session["csrf"])
}

// TestResolveBrowserStorage_FromStaticSecret proves the capture-once parity
// wiring end to end at the provider layer: a static WebStorage secret (as built
// from a captured session) flows through a real AuthProvider and is surfaced to
// the headless storage resolver.
func TestResolveBrowserStorage_FromStaticSecret(t *testing.T) {
	store := &authx.Authx{
		ID: "capture",
		Secrets: []authx.Secret{{
			Type:           string(authx.WebStorageAuth),
			Domains:        []string{"app.example.com"},
			LocalStorage:   map[string]string{"jwt": "SEEDED"},
			SessionStorage: map[string]string{"csrf": "TOK"},
		}},
	}
	provider, err := authprovider.NewStoreAuthProvider(store, nil, nil)
	require.NoError(t, err)

	target, _ := urlutil.Parse("https://app.example.com/dashboard")
	local, session := resolveBrowserStorage(provider, target)
	require.Equal(t, "SEEDED", local["jwt"])
	require.Equal(t, "TOK", session["csrf"])

	// A different host must not receive the captured storage.
	other, _ := urlutil.Parse("https://other.example.com/")
	l2, s2 := resolveBrowserStorage(provider, other)
	require.Nil(t, l2)
	require.Nil(t, s2)
}

func TestResolveBrowserStorage_NoStorageStrategies(t *testing.T) {
	provider := &fakeStorageProvider{strategies: []authx.AuthStrategy{
		authx.NewBearerTokenAuthStrategy(&authx.Secret{Type: "BearerToken", Token: "t"}),
	}}
	target, _ := urlutil.Parse("https://app.example.com/")
	local, session := resolveBrowserStorage(provider, target)
	require.Nil(t, local)
	require.Nil(t, session)
}

func TestBuildStorageInjectorJS(t *testing.T) {
	js := buildStorageInjectorJS("https://app.example.com",
		map[string]string{"jwt": "abc"},
		map[string]string{"csrf": "xyz"},
	)
	require.Contains(t, js, `"https://app.example.com"`, "must guard on origin")
	require.Contains(t, js, "window.location.origin", "must compare document origin")
	require.Contains(t, js, "localStorage.setItem", "must set localStorage")
	require.Contains(t, js, "sessionStorage.setItem", "must set sessionStorage")
	require.Contains(t, js, `"jwt":"abc"`)
	require.Contains(t, js, `"csrf":"xyz"`)
	// Must be a self-executing statement (EvalOnNewDocument runs the source
	// directly, so a bare function would never execute).
	require.True(t, strings.HasPrefix(strings.TrimSpace(js), "(function"))
	require.True(t, strings.HasSuffix(strings.TrimSpace(js), "})();"))
}

// TestApplyAuthWebStorage_E2E proves end to end that captured web storage is
// seeded into a real scanned page before its scripts run: the served page reads
// localStorage on load, and the value must be the one carried by the auth
// provider's WebStorageAuthStrategy. Skipped without a system Chrome.
func TestApplyAuthWebStorage_E2E(t *testing.T) {
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("no system chrome/chromium found; skipping headless storage-replay e2e")
	}

	const page = `<html><body><div id="out"></div>
<script>document.getElementById('out').innerText = (window.localStorage.getItem('jwt') || 'none') + '|' + (window.sessionStorage.getItem('csrf') || 'none');</script>
</body></html>`

	opts := &types.Options{AllowLocalFileAccess: true}
	require.NoError(t, protocolstate.Init(opts))

	browser, err := New(&types.Options{ShowBrowser: false, UseInstalledChrome: true})
	require.NoError(t, err, "could not create browser")
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.NoError(t, err)
	defer func() { _ = instance.Close() }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, page)
	}))
	defer ts.Close()

	provider := &fakeStorageProvider{strategies: []authx.AuthStrategy{
		authx.NewWebStorageAuthStrategy(
			map[string]string{"jwt": "SEEDED-JWT"},
			map[string]string{"csrf": "SEEDED-CSRF"},
		),
	}}

	input := contextargs.NewWithInput(context.Background(), ts.URL)
	input.CookieJar, err = cookiejar.New(nil)
	require.NoError(t, err)

	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
	}

	_, p, err := instance.Run(input, actions, nil, &Options{
		Timeout:      30 * time.Second,
		Options:      opts,
		AuthProvider: provider,
	})
	require.NoError(t, err)
	defer func() {
		if p != nil {
			p.Close()
		}
	}()

	out, err := p.Page().MustElement("#out").Text()
	require.NoError(t, err)
	require.Equal(t, "SEEDED-JWT|SEEDED-CSRF", strings.TrimSpace(out), "page should read the seeded local/session storage")
}
