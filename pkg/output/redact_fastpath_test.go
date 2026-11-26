package output

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The literal-presence fast path must never change redaction outcomes: text
// without key-shaped content passes through untouched, and keys present in any
// letter case are still masked exactly.
func TestRedactFastPathEquivalence(t *testing.T) {
	keys := []string{"Authorization", "X-Api-Key", "password"}

	// No key-shaped text: returned unchanged.
	clean := "HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n<html>nothing sensitive</html>"
	require.Equal(t, clean, redactKeys(clean, keys))

	// Keys in upper, lower and mixed case are all masked.
	for _, in := range []string{
		"Authorization: Bearer abc\r\n",
		"authorization: bearer abc\r\n",
		"AUTHORIZATION: Bearer abc\r\n",
		"aUtHoRiZaTiOn: Bearer abc\r\n",
		"X-Api-Key: deadbeef\r\n",
		"x-api-key: deadbeef\r\n",
		"GET /?password=hunter2 HTTP/1.1",
		"GET /?PASSWORD=hunter2 HTTP/1.1",
	} {
		out := redactKeys(in, keys)
		require.Contains(t, out, "***", in)
		require.NotContains(t, out, "abc", in)
		require.NotContains(t, out, "deadbeef", in)
		require.NotContains(t, out, "hunter2", in)
	}

	// A key appearing as a substring of unrelated words still masks only the
	// credential shapes; surrounding text survives.
	mixed := "the word authorization appears here\r\nAuthorization: Bearer abc\r\n"
	out := redactKeys(mixed, keys)
	require.Contains(t, out, "the word authorization appears here")
	require.Contains(t, out, "Authorization: ***")

	// Adjacent cookie pairs both mask.
	require.Equal(t,
		"Cookie: password=***; session=abc\r\n",
		redactKeys("Cookie: password=x; session=abc\r\n", keys),
	)
}

// A key with regex metacharacters is treated literally in both the fast path
// and the patterns.
func TestRedactFastPathMetacharKey(t *testing.T) {
	in := "a.b=cdef\r\n"
	require.Equal(t, "a.b=***\r\n", redactKeys(in, []string{"a.b"}))
	require.Equal(t, in, redactKeys(in, []string{"a+b"}))
}

// BenchmarkRedactWithSet measures the fast path on a large credential-free body.
func BenchmarkRedactWithSet(b *testing.B) {
	body := "HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n" + strings.Repeat("<div>lorem ipsum dolor sit amet</div>", 1500)
	set := compileRedactPatterns([]string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-Api-Key"})
	b.SetBytes(int64(len(body)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		redactWithSet(body, set)
	}
}
