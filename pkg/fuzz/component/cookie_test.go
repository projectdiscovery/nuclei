package component

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/stretchr/testify/require"
)

func TestCookieComponentPreservesRawPayload(t *testing.T) {
	for _, payload := range []string{"old'", `old"`, `old";probe=value`} {
		t.Run(payload, func(t *testing.T) {
			req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
			require.NoError(t, err)
			req.Header.Set("Cookie", "session=old; preference=dark")
			cookies := NewCookie()
			parsed, err := cookies.Parse(req)
			require.NoError(t, err)
			require.True(t, parsed)
			require.NoError(t, cookies.SetValue("session", payload))
			rebuilt, err := cookies.Rebuild()
			require.NoError(t, err)
			require.Equal(t, "session="+payload+"; preference=dark", rebuilt.Header.Get("Cookie"))
			require.Equal(t, "session=old; preference=dark", req.Header.Get("Cookie"))
		})
	}
}

func TestCookieComponentRejectsHeaderNewlines(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	req, err := retryablehttp.NewRequest(http.MethodGet, server.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Cookie", "session=old")
	cookies := NewCookie()
	parsed, err := cookies.Parse(req)
	require.NoError(t, err)
	require.True(t, parsed)
	require.NoError(t, cookies.SetValue("session", "old\r\nX-Injected: yes"))
	rebuilt, err := cookies.Rebuild()
	require.NoError(t, err)
	resp, err := server.Client().Do(rebuilt.Request)
	if resp != nil {
		require.NoError(t, resp.Body.Close())
	}
	require.ErrorContains(t, err, "invalid header field value")
	require.Equal(t, int32(0), requests.Load())
}

func TestCookieComponent(t *testing.T) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	cookie := &http.Cookie{
		Name:  "session",
		Value: "test-session",
	}
	req.AddCookie(cookie)

	cookieComponent := NewCookie() // Assuming you have a function like this for creating a new cookie component
	_, err = cookieComponent.Parse(req)
	if err != nil {
		t.Fatal(err)
	}

	var cookieNames []string
	var cookieValues []string
	_ = cookieComponent.Iterate(func(key string, value interface{}) error {
		cookieNames = append(cookieNames, key)
		switch v := value.(type) {
		case string:
			cookieValues = append(cookieValues, v)
		case []string:
			cookieValues = append(cookieValues, v...)
		}
		return nil
	})

	require.Equal(t, []string{"session"}, cookieNames, "unexpected cookie names")
	require.Equal(t, []string{"test-session"}, cookieValues, "unexpected cookie values")

	err = cookieComponent.SetValue("session", "new-session")
	if err != nil {
		t.Fatal(err)
	}

	rebuilt, err := cookieComponent.Rebuild()
	if err != nil {
		t.Fatal(err)
	}

	// Assuming the Rebuild function will reconstruct the entire request and also set the modified cookies
	newCookie, _ := rebuilt.Cookie("session")
	require.Equal(t, "new-session", newCookie.Value, "unexpected cookie value")
}

func BenchmarkCookieComponentRebuild(b *testing.B) {
	req, err := retryablehttp.NewRequest(http.MethodGet, "https://example.com", nil)
	require.NoError(b, err)
	req.Header.Set("Cookie", "session=old; preference=dark")
	cookies := NewCookie()
	parsed, err := cookies.Parse(req)
	require.NoError(b, err)
	require.True(b, parsed)
	require.NoError(b, cookies.SetValue("session", "old'"))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cookies.Rebuild(); err != nil {
			b.Fatal(err)
		}
	}
}
