package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	urlutil "github.com/projectdiscovery/utils/url"
	"github.com/stretchr/testify/require"
)

// recordingInspector is an AuthStrategy + ResponseInspector that records the
// status codes the engine forwards to it, to verify response-status re-auth.
type recordingInspector struct {
	mu       sync.Mutex
	statuses []int
	reauthOn int
}

func (r *recordingInspector) Apply(*http.Request)              {}
func (r *recordingInspector) ApplyOnRR(*retryablehttp.Request) {}
func (r *recordingInspector) OnResponse(status int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.statuses = append(r.statuses, status)
	return status == r.reauthOn
}
func (r *recordingInspector) seen() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.statuses...)
}

// inspectorProvider returns the recording inspector for any URL.
type inspectorProvider struct{ insp *recordingInspector }

func (p *inspectorProvider) LookupAddr(string) []authx.AuthStrategy {
	return []authx.AuthStrategy{p.insp}
}
func (p *inspectorProvider) LookupURL(*url.URL) []authx.AuthStrategy {
	return []authx.AuthStrategy{p.insp}
}
func (p *inspectorProvider) LookupURLX(*urlutil.URL) []authx.AuthStrategy {
	return []authx.AuthStrategy{p.insp}
}
func (p *inspectorProvider) GetTemplatePaths() []string { return nil }
func (p *inspectorProvider) PreFetchSecrets() error     { return nil }
func (p *inspectorProvider) Close()                     {}

func TestNotifyAuthResponse(t *testing.T) {
	insp := &recordingInspector{reauthOn: 401}
	target, _ := urlutil.Parse("https://app.example.com/")
	p := &Page{
		options:  &Options{AuthProvider: &inspectorProvider{insp: insp}},
		inputURL: target,
	}
	p.notifyAuthResponse(401)
	p.notifyAuthResponse(200)
	require.Equal(t, []int{401, 200}, insp.seen(), "every navigation status must be forwarded to the inspector")
}

func TestNotifyAuthResponse_NilSafe(t *testing.T) {
	// Must not panic with no provider / no input URL.
	(&Page{}).notifyAuthResponse(401)
	(&Page{options: &Options{}}).notifyAuthResponse(401)
}

// TestNotifyAuthResponse_E2E proves the full chain: a real navigation that
// returns 401 is forwarded to the auth provider's response inspector, so
// reauth-status-codes works for headless scans (not just HTTP).
func TestNotifyAuthResponse_E2E(t *testing.T) {
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("no system chrome/chromium found; skipping headless reauth e2e")
	}

	opts := &types.Options{AllowLocalFileAccess: true}
	require.NoError(t, protocolstate.Init(opts))

	browser, err := New(&types.Options{ShowBrowser: false, UseInstalledChrome: true})
	require.NoError(t, err)
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.NoError(t, err)
	defer func() { _ = instance.Close() }()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintln(w, "<html><body>unauthorized</body></html>")
	}))
	defer ts.Close()

	insp := &recordingInspector{reauthOn: http.StatusUnauthorized}
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
		AuthProvider: &inspectorProvider{insp: insp},
	})
	require.NoError(t, err)
	defer func() {
		if p != nil {
			p.Close()
		}
	}()

	require.Contains(t, insp.seen(), http.StatusUnauthorized, "401 navigation must be forwarded to the auth response inspector")
}
