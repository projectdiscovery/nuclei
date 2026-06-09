package autologin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// capturePage already "logs the user in" on GET (sets a session cookie and seeds
// web storage via JS), so a test can drive CaptureOnce without simulating manual
// interaction: the ready() callback simply returns once the page has loaded.
const capturePage = `<html><head><title>App</title></head><body>
<h1>welcome dave</h1>
<script>
  window.localStorage.setItem('auth_token', 'eyJhbGciOiJI.payload.sig');
  window.sessionStorage.setItem('csrf', 'abc123');
</script></body></html>`

func TestCaptureOnce_E2E(t *testing.T) {
	requireChrome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-dave", Path: "/"})
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, capturePage)
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var readyCalled bool
	session, err := CaptureOnce(ctx, Config{
		LoginURL:   srv.URL + "/login",
		TokenRegex: `(eyJ[A-Za-z0-9._-]+)`,
	}, func() error {
		readyCalled = true // stands in for the user pressing Enter after logging in
		return nil
	})
	require.NoError(t, err)
	require.True(t, readyCalled, "ready callback must be invoked before capture")

	names := map[string]string{}
	for _, c := range session.Cookies {
		names[c.Name] = c.Value
	}
	require.Equal(t, "sess-dave", names["session"], "session cookie must be captured")
	require.Equal(t, "eyJhbGciOiJI.payload.sig", session.LocalStorage["auth_token"], "localStorage must be captured")
	require.Equal(t, "abc123", session.SessionStorage["csrf"], "sessionStorage must be captured")
	require.Equal(t, "eyJhbGciOiJI.payload.sig", session.Token, "token must be extracted")
}

func TestCaptureOnce_ReadyErrorAborts(t *testing.T) {
	requireChrome(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "<html><body>login</body></html>")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := CaptureOnce(ctx, Config{LoginURL: srv.URL + "/login"}, func() error {
		return errors.New("user cancelled")
	})
	require.Error(t, err, "a ready() error must abort the capture")
}

func TestCaptureOnce_Validation(t *testing.T) {
	_, err := CaptureOnce(context.Background(), Config{LoginURL: "https://x"}, nil)
	require.Error(t, err, "nil ready must error")

	_, err = CaptureOnce(context.Background(), Config{}, func() error { return nil })
	require.Error(t, err, "missing login-url must error")
}
