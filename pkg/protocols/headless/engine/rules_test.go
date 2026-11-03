package engine

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSyncCookies_NilURL_DoesNotPanic(t *testing.T) {
	sharedJar, err := cookiejar.New(nil)
	require.NoError(t, err)

	clientJar, err := cookiejar.New(nil)
	require.NoError(t, err)

	// Ensure calling with nil reqURL never panics with nil pointer dereference
	require.NotPanics(t, func() {
		syncRequestCookies(sharedJar, clientJar, nil)
	})

	require.NotPanics(t, func() {
		syncResponseCookies(sharedJar, clientJar, nil)
	})

	// Ensure calling with nil jars never panics
	require.NotPanics(t, func() {
		syncRequestCookies(nil, clientJar, &url.URL{Scheme: "http", Host: "example.com"})
	})

	require.NotPanics(t, func() {
		syncRequestCookies(sharedJar, nil, &url.URL{Scheme: "http", Host: "example.com"})
	})

	require.NotPanics(t, func() {
		syncResponseCookies(nil, clientJar, &url.URL{Scheme: "http", Host: "example.com"})
	})

	require.NotPanics(t, func() {
		syncResponseCookies(sharedJar, nil, &url.URL{Scheme: "http", Host: "example.com"})
	})
}

func TestSyncCookies_TransfersCookiesBetweenJars(t *testing.T) {
	sharedJar, err := cookiejar.New(nil)
	require.NoError(t, err)

	clientJar, err := cookiejar.New(nil)
	require.NoError(t, err)

	testURL, err := url.Parse("https://example.com/test")
	require.NoError(t, err)

	// Populate shared jar
	sharedJar.SetCookies(testURL, []*http.Cookie{
		{Name: "session", Value: "secret123", Path: "/"},
	})

	// Sync to client jar
	syncRequestCookies(sharedJar, clientJar, testURL)

	clientCookies := clientJar.Cookies(testURL)
	require.Len(t, clientCookies, 1)
	require.Equal(t, "session", clientCookies[0].Name)
	require.Equal(t, "secret123", clientCookies[0].Value)

	// Now client jar receives new cookie from response
	clientJar.SetCookies(testURL, []*http.Cookie{
		{Name: "csrf", Value: "token456", Path: "/"},
	})

	// Sync back to shared jar
	syncResponseCookies(sharedJar, clientJar, testURL)

	updatedSharedCookies := sharedJar.Cookies(testURL)
	require.Len(t, updatedSharedCookies, 2)
}
