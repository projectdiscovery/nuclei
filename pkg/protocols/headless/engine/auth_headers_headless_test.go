package engine

import (
	"context"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-rod/rod/lib/launcher"
	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/authx"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestHeadlessAuthHeaders_DoNotLeakCrossOrigin(t *testing.T) {
	if _, ok := launcher.LookPath(); !ok {
		t.Skip("no system chrome/chromium found; skipping headless auth header e2e")
	}

	opts := &types.Options{AllowLocalFileAccess: true}
	require.NoError(t, protocolstate.Init(opts))

	browser, err := New(&types.Options{ShowBrowser: false, UseInstalledChrome: true})
	require.NoError(t, err)
	defer browser.Close()

	instance, err := browser.NewInstance()
	require.NoError(t, err)
	defer func() { _ = instance.Close() }()

	crossOriginHeader := make(chan string, 1)
	crossOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case crossOriginHeader <- r.Header.Get("Authorization"):
		default:
		}
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = fmt.Fprintln(w, "window.crossOriginLoaded = true;")
	}))
	defer crossOrigin.Close()

	sameOriginHeader := make(chan string, 1)
	sameOrigin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sameOriginHeader <- r.Header.Get("Authorization"):
		default:
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprintf(w, `<html><body><script src="%s/resource.js"></script></body></html>`, crossOrigin.URL)
	}))
	defer sameOrigin.Close()

	input := contextargs.NewWithInput(context.Background(), sameOrigin.URL)
	input.CookieJar, err = cookiejar.New(nil)
	require.NoError(t, err)
	actions := []*Action{
		{ActionType: ActionTypeHolder{ActionType: ActionNavigate}, Data: map[string]string{"url": "{{BaseURL}}"}},
		{ActionType: ActionTypeHolder{ActionType: ActionWaitLoad}},
	}
	provider := &mockAuthProvider{strategies: []authx.AuthStrategy{
		authx.NewHeadersAuthStrategy(&authx.Secret{Headers: []authx.KV{{Key: "Authorization", Value: "Bearer secret"}}}),
	}}

	_, page, err := instance.Run(input, actions, nil, &Options{
		Timeout:      30 * time.Second,
		Options:      opts,
		AuthProvider: provider,
	})
	require.NoError(t, err)
	if page != nil {
		defer page.Close()
	}

	select {
	case header := <-sameOriginHeader:
		require.Equal(t, "Bearer secret", header)
	case <-time.After(5 * time.Second):
		t.Fatal("same-origin document request was not observed")
	}
	select {
	case header := <-crossOriginHeader:
		require.Empty(t, header, "auth header leaked to cross-origin subresource")
	case <-time.After(5 * time.Second):
		t.Fatal("cross-origin subresource request was not observed")
	}
}
