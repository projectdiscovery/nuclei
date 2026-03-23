package hosttechcache

import (
	"fmt"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// mustNotSkip fails the test if ShouldSkipTemplate returns true.
func mustNotSkip(t *testing.T, c *HostTechCache, host string, tags []string, msg string) {
	t.Helper()
	if c.ShouldSkipTemplate(host, tags) {
		t.Errorf("UNEXPECTED SKIP — %s (host=%q tags=%v)", msg, host, tags)
	}
}

// mustSkip fails the test if ShouldSkipTemplate returns false.
func mustSkip(t *testing.T, c *HostTechCache, host string, tags []string, msg string) {
	t.Helper()
	if !c.ShouldSkipTemplate(host, tags) {
		t.Errorf("EXPECTED SKIP — %s (host=%q tags=%v)", msg, host, tags)
	}
}

// ---------------------------------------------------------------------------
// 1. Basic Apache detection
// ---------------------------------------------------------------------------

func TestHostTechCache_ApacheExactMatch(t *testing.T) {
	c := NewHostTechCache()
	c.RecordServerHeader("http://example.com", "Apache")

	mustSkip(t, c, "http://example.com", []string{"nginx"}, "non-apache tag should be skipped")
	mustNotSkip(t, c, "http://example.com", []string{"apache"}, "apache tag must not be skipped")
}

func TestHostTechCache_ApacheVersionString(t *testing.T) {
	// Real-world Server header: "Apache/2.4.51 (Unix) OpenSSL/1.1.1l"
	c := NewHostTechCache()
	c.RecordServerHeader("https://target.io", "Apache/2.4.51 (Unix) OpenSSL/1.1.1l")

	mustSkip(t, c, "https://target.io", []string{"iis", "xss"}, "non-apache template should be skipped")
	mustNotSkip(t, c, "https://target.io", []string{"apache", "cve"}, "template tagged apache+cve must run")
}

func TestHostTechCache_ApacheCaseInsensitive(t *testing.T) {
	variants := []string{
		"APACHE/2.4",
		"Apache/2.4",
		"apache/2.4",
		"aPaChE",
	}
	for _, hdr := range variants {
		c := NewHostTechCache()
		c.RecordServerHeader("http://host.test", hdr)

		mustSkip(t, c, "http://host.test", []string{"nginx"}, fmt.Sprintf("header %q: non-apache should skip", hdr))
		mustNotSkip(t, c, "http://host.test", []string{"apache"}, fmt.Sprintf("header %q: apache tag must not skip", hdr))
	}
}

// ---------------------------------------------------------------------------
// 2. No hint → never skip
// ---------------------------------------------------------------------------

func TestHostTechCache_UnknownHostNeverSkipped(t *testing.T) {
	c := NewHostTechCache()
	// Nothing recorded for "http://unknown.host"
	mustNotSkip(t, c, "http://unknown.host", []string{"xss", "sqli"}, "host with no hint must never be skipped")
}

func TestHostTechCache_EmptyServerHeader(t *testing.T) {
	c := NewHostTechCache()
	c.RecordServerHeader("http://silent.host", "")

	mustNotSkip(t, c, "http://silent.host", []string{"xss"}, "empty Server header must not create a hint")
}

func TestHostTechCache_UnrecognisedServerHeader(t *testing.T) {
	c := NewHostTechCache()
	c.RecordServerHeader("http://custom.host", "MyPrivateServer/3.0")

	mustNotSkip(t, c, "http://custom.host", []string{"xss", "sqli"}, "unknown server value must not trigger filtering")
}

// ---------------------------------------------------------------------------
// 3. Tag matching logic
// ---------------------------------------------------------------------------

func TestHostTechCache_TemplateWithNoTags(t *testing.T) {
	// A template with zero tags should be skipped once Apache is detected —
	// it carries no evidence of Apache relevance.
	c := NewHostTechCache()
	c.RecordServerHeader("http://example.com", "Apache/2.2")

	mustSkip(t, c, "http://example.com", []string{}, "tagless template should be skipped on Apache host")
	mustSkip(t, c, "http://example.com", nil, "nil-tag template should be skipped on Apache host")
}

func TestHostTechCache_MultiTagTemplateOneMatches(t *testing.T) {
	// Template tagged ["rce", "apache", "cve-2021"] — should NOT be skipped.
	c := NewHostTechCache()
	c.RecordServerHeader("http://example.com", "Apache/2.4")

	mustNotSkip(t, c, "http://example.com", []string{"rce", "apache", "cve-2021"},
		"template with apache among multiple tags must run")
}

func TestHostTechCache_MultiTagTemplateNoneMatch(t *testing.T) {
	// Template tagged ["rce", "nginx", "cve-2023"] — should be skipped.
	c := NewHostTechCache()
	c.RecordServerHeader("http://example.com", "Apache/2.4")

	mustSkip(t, c, "http://example.com", []string{"rce", "nginx", "cve-2023"},
		"template without apache tag must be skipped on Apache host")
}

func TestHostTechCache_TagComparisonIsCaseInsensitive(t *testing.T) {
	c := NewHostTechCache()
	c.RecordServerHeader("http://example.com", "Apache/2.4")

	// Template tags written in various cases should all match.
	for _, tag := range []string{"Apache", "APACHE", "aPaChE"} {
		mustNotSkip(t, c, "http://example.com", []string{tag},
			fmt.Sprintf("tag %q must match the apache hint case-insensitively", tag))
	}
}

// ---------------------------------------------------------------------------
// 4. Host isolation (different hosts don't bleed into each other)
// ---------------------------------------------------------------------------

func TestHostTechCache_PerHostIsolation(t *testing.T) {
	c := NewHostTechCache()
	c.RecordServerHeader("http://apache-host.com", "Apache/2.4")
	// nginx-host.com deliberately has no hint recorded.

	// apache-host: non-apache template skipped
	mustSkip(t, c, "http://apache-host.com", []string{"nginx"}, "apache-host: nginx template should skip")

	// nginx-host: same template must NOT be skipped (no hint)
	mustNotSkip(t, c, "http://nginx-host.com", []string{"nginx"}, "nginx-host: nginx template must run (no hint)")

	// apache-host: apache template not skipped
	mustNotSkip(t, c, "http://apache-host.com", []string{"apache"}, "apache-host: apache template must run")
}

func TestHostTechCache_OverwriteHint(t *testing.T) {
	// If a second response arrives with a different Server header for the same
	// host (e.g. redirect to a different backend), the newer hint wins.
	c := NewHostTechCache()
	c.RecordServerHeader("http://example.com", "Apache/2.4")
	c.RecordServerHeader("http://example.com", "MyPrivateServer/1.0") // overwrites — no recognised tech

	// After the overwrite the hint for example.com should be gone.
	mustNotSkip(t, c, "http://example.com", []string{"nginx"},
		"after overwrite with unknown server, no filtering should apply")
}

// ---------------------------------------------------------------------------
// 5. Concurrency safety
// ---------------------------------------------------------------------------

func TestHostTechCache_ConcurrentWrites(t *testing.T) {
	c := NewHostTechCache()

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("http://host-%d.example.com", i)
			c.RecordServerHeader(host, "Apache/2.4")
		}(i)
	}
	wg.Wait()

	// Every host should now have the apache hint.
	for i := 0; i < goroutines; i++ {
		host := fmt.Sprintf("http://host-%d.example.com", i)
		mustSkip(t, c, host, []string{"nginx"}, fmt.Sprintf("host %s: non-apache should skip after concurrent write", host))
		mustNotSkip(t, c, host, []string{"apache"}, fmt.Sprintf("host %s: apache should not skip after concurrent write", host))
	}
}

func TestHostTechCache_ConcurrentReadsAndWrites(t *testing.T) {
	c := NewHostTechCache()

	const writers = 20
	const readers = 40

	var wg sync.WaitGroup
	wg.Add(writers + readers)

	// Writers record Apache for even-numbered hosts.
	for i := 0; i < writers; i++ {
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("http://host-%d.test", i*2) // even hosts
			c.RecordServerHeader(host, "Apache/2.4")
		}(i)
	}

	// Readers call ShouldSkipTemplate concurrently; we just verify no panic/race.
	for i := 0; i < readers; i++ {
		go func(i int) {
			defer wg.Done()
			host := fmt.Sprintf("http://host-%d.test", i)
			// Result may be true or false depending on scheduling; we don't assert
			// here — the race detector will catch any data races.
			_ = c.ShouldSkipTemplate(host, []string{"apache"})
		}(i)
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// 6. NewHostTechCache constructor
// ---------------------------------------------------------------------------

func TestNewHostTechCache_InitialisedEmpty(t *testing.T) {
	c := NewHostTechCache()
	if c == nil {
		t.Fatal("NewHostTechCache returned nil")
	}
	// Freshly created cache should never skip anything.
	mustNotSkip(t, c, "http://any.host", []string{"apache"}, "fresh cache must never skip")
}

// ---------------------------------------------------------------------------
// 7. Edge / boundary cases
// ---------------------------------------------------------------------------

func TestHostTechCache_WhitespaceServerHeader(t *testing.T) {
	c := NewHostTechCache()
	c.RecordServerHeader("http://ws.host", "   ")

	mustNotSkip(t, c, "http://ws.host", []string{"xss"}, "whitespace-only Server header must not trigger filtering")
}

func TestHostTechCache_ServerHeaderContainsApacheAsSubstring(t *testing.T) {
	// "NotApache/1.0" still contains the substring "apache" in lowercase;
	// the current implementation detects it. This test documents that behaviour
	// explicitly so a future change to tighten the match is a conscious decision.
	c := NewHostTechCache()
	c.RecordServerHeader("http://sub.host", "NotApache/1.0")

	mustSkip(t, c, "http://sub.host", []string{"nginx"},
		"'NotApache' contains 'apache' substring — current behaviour skips non-apache templates")
	mustNotSkip(t, c, "http://sub.host", []string{"apache"},
		"'NotApache' contains 'apache' substring — apache-tagged template must still run")
}

func TestHostTechCache_MultipleHostsIndependent(t *testing.T) {
	c := NewHostTechCache()

	hosts := map[string]string{
		"http://alpha.test":   "Apache/2.4",
		"http://beta.test":    "nginx/1.18",     // unrecognised → no hint
		"http://gamma.test":   "",               // empty → no hint
		"http://delta.test":   "Apache/1.3.42",
	}

	for host, header := range hosts {
		c.RecordServerHeader(host, header)
	}

	// Alpha and delta → apache hints recorded.
	for _, host := range []string{"http://alpha.test", "http://delta.test"} {
		mustSkip(t, c, host, []string{"nginx"}, host+": nginx should skip (apache host)")
		mustNotSkip(t, c, host, []string{"apache"}, host+": apache should not skip")
	}

	// Beta and gamma → no hints; nothing skipped.
	for _, host := range []string{"http://beta.test", "http://gamma.test"} {
		mustNotSkip(t, c, host, []string{"nginx"}, host+": nginx must not skip (no hint)")
		mustNotSkip(t, c, host, []string{"apache"}, host+": apache must not skip (no hint)")
	}
}