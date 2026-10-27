package authx

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCookieAppliesToRequest_Scope(t *testing.T) {
	t.Run("unscoped cookies always apply", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://app.example.com/dashboard", nil)
		require.True(t, cookieAppliesToRequest(Cookie{Key: "s", Value: "1"}, req.URL))
	})

	t.Run("domain and path filter", func(t *testing.T) {
		c := Cookie{Key: "s", Value: "1", Domain: ".example.com", Path: "/app"}
		ok, _ := http.NewRequest(http.MethodGet, "https://api.example.com/app/x", nil)
		badHost, _ := http.NewRequest(http.MethodGet, "https://evil.com/app", nil)
		badPath, _ := http.NewRequest(http.MethodGet, "https://api.example.com/other", nil)
		require.True(t, cookieAppliesToRequest(c, ok.URL))
		require.False(t, cookieAppliesToRequest(c, badHost.URL))
		require.False(t, cookieAppliesToRequest(c, badPath.URL))
	})

	t.Run("secure cookies skip http", func(t *testing.T) {
		c := Cookie{Key: "s", Value: "1", Secure: true}
		httpsReq, _ := http.NewRequest(http.MethodGet, "https://app.example.com/", nil)
		httpReq, _ := http.NewRequest(http.MethodGet, "http://app.example.com/", nil)
		require.True(t, cookieAppliesToRequest(c, httpsReq.URL))
		require.False(t, cookieAppliesToRequest(c, httpReq.URL))
	})
}

func TestCookiesAuthStrategy_PreservesScopedCookies(t *testing.T) {
	s := NewCookiesAuthStrategy(&Secret{
		Cookies: []Cookie{
			{Key: "session", Value: "app", Domain: "app.example.com", Path: "/"},
			{Key: "session", Value: "idp", Domain: "login.example.com", Path: "/"},
			{Key: "csrf", Value: "x", Domain: "app.example.com", Path: "/login"},
		},
	})

	appReq, _ := http.NewRequest(http.MethodGet, "https://app.example.com/dashboard", nil)
	s.Apply(appReq)
	got := map[string]string{}
	for _, c := range appReq.Cookies() {
		got[c.Name] = c.Value
	}
	require.Equal(t, "app", got["session"], "app-scoped session must apply")
	require.NotContains(t, got, "csrf", "login-path csrf must not apply to /dashboard")

	idpReq, _ := http.NewRequest(http.MethodGet, "https://login.example.com/", nil)
	s.Apply(idpReq)
	got = map[string]string{}
	for _, c := range idpReq.Cookies() {
		got[c.Name] = c.Value
	}
	require.Equal(t, "idp", got["session"], "idp-scoped session must apply on idp host")
}
