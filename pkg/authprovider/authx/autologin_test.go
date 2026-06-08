package authx

import (
	"net/http"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/authprovider/autologin"
	"github.com/stretchr/testify/require"
)

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
	err := d.applyAutoLoginSession(&autologin.Session{
		Cookies: []*http.Cookie{{Name: "session", Value: "abc"}},
		Token:   "jwt-123",
	})
	require.NoError(t, err)
	require.Equal(t, string(CookiesAuth), d.Secret.Type)
	require.Len(t, d.Secrets, 1, "token should be applied as an additional bearer secret")
	require.Equal(t, string(BearerTokenAuth), d.Secrets[0].Type)
	require.Equal(t, "jwt-123", d.Secrets[0].Token)
	require.Equal(t, []string{"app.example.com"}, d.Secrets[0].Domains)
}

func TestApplyAutoLoginSession_Empty(t *testing.T) {
	d := newAutoLoginDynamic()
	err := d.applyAutoLoginSession(&autologin.Session{})
	require.Error(t, err)
}

func TestApplyAutoLoginSession_ReauthReplaces(t *testing.T) {
	d := newAutoLoginDynamic()
	// First auth: cookies + token (creates an extra bearer secret).
	require.NoError(t, d.applyAutoLoginSession(&autologin.Session{
		Cookies: []*http.Cookie{{Name: "session", Value: "v1"}},
		Token:   "jwt-1",
	}))
	require.Len(t, d.Secrets, 1)

	// Re-auth: cookies only -> the previous bearer secret and cookies must be
	// fully replaced, not appended.
	require.NoError(t, d.applyAutoLoginSession(&autologin.Session{
		Cookies: []*http.Cookie{{Name: "session", Value: "v2"}},
	}))
	require.Empty(t, d.Secrets, "stale bearer secret must be cleared on re-auth")
	require.Len(t, d.Secret.Cookies, 1)
	require.Equal(t, "v2", d.Secret.Cookies[0].Value, "cookie value must be refreshed")
}
