package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddCookieIgnore(t *testing.T) {
	exact := map[string]struct{}{}
	prefixes := map[string]struct{}{}
	for _, name := range []string{"_ga", " _gid ", "_ga_*", "(?i)ltpatoken", "_circle_session:", "a*b", "*", ""} {
		addCookieIgnore(exact, prefixes, name)
	}
	require.Equal(t, []string{"_ga", "_gid"}, sortedKeys(exact))
	require.Equal(t, []string{"_ga_"}, sortedKeys(prefixes))
}

func TestIsSessionCookie(t *testing.T) {
	for _, name := range []string{"JSESSIONID", "PHPSESSID", "ASP.NET_SessionId", "_gitlab_session", "__host-next-auth.csrf-token", "XSRF-TOKEN", "connect.sid", "laravel_session", "remember_user_token", "CFID", "wordpress_logged_in_abc", "wordpress_*", "intercom-session-*", "cakephp", "frontend", "dssignin", "publiccms_user"} {
		require.True(t, isSessionCookie(name), name)
	}
	for _, name := range []string{"_ga", "_ga_*", "_gid", "__utmz", "AWSALB", "_fbp", "hubspotutk", "_pk_ses", "optimizelyEndUserId"} {
		require.False(t, isSessionCookie(name), name)
	}
}

func TestAddCookieIgnoreLowercases(t *testing.T) {
	exact := map[string]struct{}{}
	prefixes := map[string]struct{}{}
	addCookieIgnore(exact, prefixes, "AWSALB")
	addCookieIgnore(exact, prefixes, "_GA_*")
	require.Equal(t, []string{"awsalb"}, sortedKeys(exact))
	require.Equal(t, []string{"_ga_"}, sortedKeys(prefixes))
}

func TestDefaultOutPath(t *testing.T) {
	out := defaultOutPath()
	require.Equal(t, "ignorelists.gen.go", filepath.Base(out))
	require.Equal(t, "component", filepath.Base(filepath.Dir(out)))
	_, err := os.Stat(out)
	require.NoError(t, err)
}
