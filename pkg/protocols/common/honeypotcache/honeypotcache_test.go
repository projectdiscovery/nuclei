package honeypotcache

import (
	"fmt"
	"sync"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/stretchr/testify/require"
)

func makeCtx(input string) *contextargs.Context {
	ctx := contextargs.New(nil)
	ctx.MetaInput = &contextargs.MetaInput{Input: input}
	return ctx
}

func TestCacheMarkAndCheck(t *testing.T) {
	c := New(5, false, 0)
	ctx := makeCtx("http://192.168.1.1/path")

	for i := 0; i < 4; i++ {
		c.MarkMatch(ctx, fmt.Sprintf("template-%d", i))
		require.False(t, c.Check(ctx), "should not flag before threshold")
	}
	c.MarkMatch(ctx, "template-4")
	require.True(t, c.Check(ctx), "should flag at threshold")
}

func TestCacheDisabled(t *testing.T) {
	c := New(5, true, 0)
	ctx := makeCtx("192.168.1.1")
	for i := 0; i < 100; i++ {
		c.MarkMatch(ctx, fmt.Sprintf("t%d", i))
	}
	require.False(t, c.Check(ctx), "disabled cache must never flag")
}

func TestCachePercentageThreshold(t *testing.T) {
	c := New(0, false, 0) // absolute threshold disabled
	// Use 20 templates — the minimum required for percentage-based detection.
	c.SetTotalTemplates(20)
	ctx := makeCtx("10.0.0.1")

	// 9/20 = 45% → below 50% threshold
	for i := 0; i < 9; i++ {
		c.MarkMatch(ctx, fmt.Sprintf("t%d", i))
	}
	require.False(t, c.Check(ctx))

	// 10/20 = 50% → at threshold
	c.MarkMatch(ctx, "t9")
	require.True(t, c.Check(ctx))
}

func TestCachePercentageBelowMinTotal(t *testing.T) {
	c := New(0, false, 0) // absolute threshold disabled
	// Fewer than 20 templates — percentage detection must stay silent.
	c.SetTotalTemplates(10)
	ctx := makeCtx("10.0.0.5")

	// 8/10 = 80% — would exceed threshold, but total < 20 so must not flag.
	for i := 0; i < 8; i++ {
		c.MarkMatch(ctx, fmt.Sprintf("t%d", i))
	}
	require.False(t, c.Check(ctx), "pct detection must not fire when total < minTotalForPct")
}

func TestCacheHostNormalization(t *testing.T) {
	c := New(3, false, 0)

	// All variants should resolve to the same host key.
	variants := []string{
		"http://example.com/page",
		"https://example.com:443/other",
		"example.com:80",
	}
	for i, v := range variants {
		c.MarkMatch(makeCtx(v), fmt.Sprintf("t%d", i))
	}
	// All 3 counted against "example.com" → at threshold.
	require.True(t, c.Check(makeCtx("example.com")))
}

func TestCacheUniqueTemplatesOnly(t *testing.T) {
	c := New(3, false, 0)
	ctx := makeCtx("10.0.0.2")
	// Same template ID repeated many times — should count as 1.
	for i := 0; i < 100; i++ {
		c.MarkMatch(ctx, "same-template")
	}
	require.False(t, c.Check(ctx), "duplicate template IDs must not inflate count")
}

func TestCacheConcurrentMarkMatch(t *testing.T) {
	c := New(200, false, 0)
	ctx := makeCtx("10.0.0.3")
	var wg sync.WaitGroup
	const goroutines = 50
	const perGoroutine = 4

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				c.MarkMatch(ctx, fmt.Sprintf("t-%d-%d", g, i))
			}
		}(g)
	}
	wg.Wait()

	// goroutines*perGoroutine = 200 unique IDs → exactly at threshold
	require.True(t, c.Check(ctx))
}

func TestCheckSignature(t *testing.T) {
	cases := []struct {
		input   string
		want    bool
		sigName string
	}{
		{"SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2", true, "Cowrie-SSH"},
		{"this server runs cowrie honeypot", true, "Cowrie"},
		{"Dionaea multi-protocol honeypot active", true, "Dionaea"},
		{"CVE-2024-50379-CONFIRMED in response", true, "CVE-Bait"},
		{"normal nginx/1.21.4 response", false, ""},
		{"AWS Canary deployment token", false, ""}, // must NOT match
	}
	for _, tc := range cases {
		matched, name := CheckSignature(tc.input)
		require.Equal(t, tc.want, matched, "input: %q", tc.input)
		if tc.want {
			require.Equal(t, tc.sigName, name, "input: %q", tc.input)
		}
	}
}

func TestCacheNilSafe(t *testing.T) {
	var c *Cache
	ctx := makeCtx("10.0.0.4")
	// Must not panic.
	c.MarkMatch(ctx, "t1")
	require.False(t, c.Check(ctx))
}

func TestCacheAbsoluteMaxPrecedence(t *testing.T) {
	// maxHostMatch=30 configured; 15/20 = 75% would fire the percentage rule,
	// but the absolute limit takes precedence and 15 < 30 → must not flag.
	c := New(30, false, 0)
	c.SetTotalTemplates(20)
	ctx := makeCtx("10.0.0.6")
	for i := 0; i < 15; i++ {
		c.MarkMatch(ctx, fmt.Sprintf("t%d", i))
	}
	require.False(t, c.Check(ctx), "percentage rule must not fire when absolute max is configured and not reached")
}

func TestNormalizeHostIPv6(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"[2001:db8::1]:8080", "[2001:db8::1]"},  // bracketed IPv6 with port
		{"[::1]:443", "[::1]"},                    // bracketed loopback with port
		{"[::1]", "[::1]"},                        // bracketed, no port
		{"2001:db8::1", "2001:db8::1"},            // raw IPv6 — must not be mangled
		{"::1", "::1"},                            // raw loopback — must not be mangled
		{"example.com:8080", "example.com"},       // plain host:port
		{"example.com", "example.com"},            // plain host, no port
	}
	for _, tc := range cases {
		got := normalizeHost(tc.input)
		require.Equal(t, tc.want, got, "input: %q", tc.input)
	}
}
