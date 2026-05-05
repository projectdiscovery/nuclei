package httpclientpool

import (
	"net/http"
	"net/url"
	"testing"
)

func TestNormalizeHost(t *testing.T) {
	tests := []struct {
		name   string
		scheme string
		host   string
		want   string
	}{
		// No port
		{"http no port", "http", "example.com", "example.com"},
		{"https no port", "https", "example.com", "example.com"},

		// Default ports stripped
		{"http default port 80", "http", "example.com:80", "example.com"},
		{"https default port 443", "https", "example.com:443", "example.com"},

		// Non-default ports preserved
		{"http non-default port", "http", "example.com:8080", "example.com:8080"},
		{"https non-default port", "https", "example.com:8443", "example.com:8443"},

		// Cross-scheme default ports preserved (443 is not default for http)
		{"http with port 443", "http", "example.com:443", "example.com:443"},
		{"https with port 80", "https", "example.com:80", "example.com:80"},

		// IP addresses
		{"ipv4 no port", "http", "127.0.0.1", "127.0.0.1"},
		{"ipv4 default port", "http", "127.0.0.1:80", "127.0.0.1"},
		{"ipv4 non-default port", "http", "127.0.0.1:8080", "127.0.0.1:8080"},
		{"ipv4 https default port", "https", "10.0.0.1:443", "10.0.0.1"},

		// IPv6 addresses
		{"ipv6 no port", "http", "[::1]", "[::1]"},
		{"ipv6 default port http", "http", "[::1]:80", "[::1]"},
		{"ipv6 default port https", "https", "[::1]:443", "[::1]"},
		{"ipv6 non-default port", "https", "[::1]:8443", "[::1]:8443"},
		{"ipv6 full address default port", "http", "[2001:db8::1]:80", "[2001:db8::1]"},
		{"ipv6 full address non-default", "http", "[2001:db8::1]:9090", "[2001:db8::1]:9090"},

		// Empty host
		{"empty host", "http", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &url.URL{Scheme: tt.scheme, Host: tt.host}
			got := normalizeHost(u)
			if got != tt.want {
				t.Errorf("normalizeHost(%s://%s) = %q, want %q", tt.scheme, tt.host, got, tt.want)
			}
		})
	}
}

func TestFollowSameHostRedirectWithPort(t *testing.T) {
	tests := []struct {
		name        string
		oldURL      string
		newURL      string
		shouldAllow bool
	}{
		// Basic same host
		{"same host no port", "http://example.com/a", "http://example.com/b", true},
		{"same host same path", "http://example.com/a", "http://example.com/a", true},

		// Default port normalization (the bug from #4685)
		{"old has :80 new does not", "http://example.com:80/a", "http://example.com/b", true},
		{"new has :80 old does not", "http://example.com/a", "http://example.com:80/b", true},
		{"both have :80", "http://example.com:80/a", "http://example.com:80/b", true},
		{"old has :443 new does not https", "https://example.com:443/a", "https://example.com/b", true},
		{"new has :443 old does not https", "https://example.com/a", "https://example.com:443/b", true},
		{"both have :443 https", "https://example.com:443/a", "https://example.com:443/b", true},

		// Relative redirect (host carried from original request)
		{"relative redirect same host", "http://example.com/a", "http://example.com/target", true},

		// IP address with default port
		{"ip old has :80 new does not", "http://127.0.0.1:80/a", "http://127.0.0.1/b", true},
		{"ip new has :80 old does not", "http://127.0.0.1/a", "http://127.0.0.1:80/b", true},
		{"ip both no port", "http://127.0.0.1/a", "http://127.0.0.1/b", true},

		// Different hosts should be blocked
		{"different host", "http://example.com/a", "http://other.com/b", false},
		{"different host with port", "http://example.com:80/a", "http://other.com:80/b", false},
		{"different ip", "http://127.0.0.1/a", "http://127.0.0.2/b", false},

		// Non-default ports
		{"same non-default port", "http://example.com:8080/a", "http://example.com:8080/b", true},
		{"different non-default port", "http://example.com:8080/a", "http://example.com:9090/b", false},
		{"non-default vs no port", "http://example.com:8080/a", "http://example.com/b", false},
		{"no port vs non-default", "http://example.com/a", "http://example.com:8080/b", false},

		// Cross-scheme port (443 on http is non-default, should not strip)
		{"http port 443 vs no port", "http://example.com:443/a", "http://example.com/b", false},
		{"https port 80 vs no port", "https://example.com:80/a", "https://example.com/b", false},

		// IPv6
		{"ipv6 same host", "http://[::1]/a", "http://[::1]/b", true},
		{"ipv6 default port normalization", "http://[::1]:80/a", "http://[::1]/b", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			checkFn := makeCheckRedirectFunc(FollowSameHostRedirect, 10)
			oldReq, _ := http.NewRequest("GET", tt.oldURL, nil)
			newReq, _ := http.NewRequest("GET", tt.newURL, nil)
			err := checkFn(newReq, []*http.Request{oldReq})
			allowed := err == nil
			if allowed != tt.shouldAllow {
				t.Errorf("redirect from %q to %q: allowed=%v, want %v", tt.oldURL, tt.newURL, allowed, tt.shouldAllow)
			}
		})
	}
}

func TestFollowSameHostRedirectViaHost(t *testing.T) {
	// When via[0].Host is set (e.g. Host header override), it takes precedence over URL.Host
	checkFn := makeCheckRedirectFunc(FollowSameHostRedirect, 10)

	oldReq, _ := http.NewRequest("GET", "http://proxy.internal/a", nil)
	oldReq.Host = "example.com"
	newReq, _ := http.NewRequest("GET", "http://example.com/b", nil)

	err := checkFn(newReq, []*http.Request{oldReq})
	if err != nil {
		t.Errorf("redirect should be allowed when via[0].Host matches new host, got err: %v", err)
	}

	// Mismatch: via[0].Host differs from redirect target
	oldReq2, _ := http.NewRequest("GET", "http://proxy.internal/a", nil)
	oldReq2.Host = "other.com"
	newReq2, _ := http.NewRequest("GET", "http://example.com/b", nil)

	err = checkFn(newReq2, []*http.Request{oldReq2})
	if err == nil {
		t.Errorf("redirect should be blocked when via[0].Host differs from new host")
	}
}

func TestDontFollowRedirect(t *testing.T) {
	checkFn := makeCheckRedirectFunc(DontFollowRedirect, 10)
	oldReq, _ := http.NewRequest("GET", "http://example.com/a", nil)
	newReq, _ := http.NewRequest("GET", "http://example.com/b", nil)

	err := checkFn(newReq, []*http.Request{oldReq})
	if err != http.ErrUseLastResponse {
		t.Errorf("DontFollowRedirect should always return ErrUseLastResponse, got: %v", err)
	}
}

func TestFollowAllRedirect(t *testing.T) {
	checkFn := makeCheckRedirectFunc(FollowAllRedirect, 10)

	// Same host
	oldReq, _ := http.NewRequest("GET", "http://example.com/a", nil)
	newReq, _ := http.NewRequest("GET", "http://example.com/b", nil)
	if err := checkFn(newReq, []*http.Request{oldReq}); err != nil {
		t.Errorf("FollowAllRedirect should allow same host redirect, got: %v", err)
	}

	// Different host
	oldReq2, _ := http.NewRequest("GET", "http://example.com/a", nil)
	newReq2, _ := http.NewRequest("GET", "http://other.com/b", nil)
	if err := checkFn(newReq2, []*http.Request{oldReq2}); err != nil {
		t.Errorf("FollowAllRedirect should allow cross-host redirect, got: %v", err)
	}
}

func TestMaxRedirects(t *testing.T) {
	// Exceeding explicit max
	checkFn := makeCheckRedirectFunc(FollowAllRedirect, 2)
	req, _ := http.NewRequest("GET", "http://example.com/c", nil)
	via := make([]*http.Request, 3)
	for i := range via {
		via[i], _ = http.NewRequest("GET", "http://example.com/"+string(rune('a'+i)), nil)
	}
	if err := checkFn(req, via); err == nil {
		t.Errorf("should block after exceeding maxRedirects=2 with 3 via requests")
	}

	// Within explicit max
	checkFn2 := makeCheckRedirectFunc(FollowAllRedirect, 5)
	via2 := make([]*http.Request, 3)
	for i := range via2 {
		via2[i], _ = http.NewRequest("GET", "http://example.com/"+string(rune('a'+i)), nil)
	}
	if err := checkFn2(req, via2); err != nil {
		t.Errorf("should allow within maxRedirects=5 with 3 via requests, got: %v", err)
	}

	// maxRedirects=0 uses default (10)
	checkFn3 := makeCheckRedirectFunc(FollowAllRedirect, 0)
	via3 := make([]*http.Request, 11)
	for i := range via3 {
		via3[i], _ = http.NewRequest("GET", "http://example.com/x", nil)
	}
	if err := checkFn3(req, via3); err == nil {
		t.Errorf("should block after exceeding default maxRedirects (10) with 11 via requests")
	}

	via4 := make([]*http.Request, 9)
	for i := range via4 {
		via4[i], _ = http.NewRequest("GET", "http://example.com/x", nil)
	}
	if err := checkFn3(req, via4); err != nil {
		t.Errorf("should allow within default maxRedirects (10) with 9 via requests, got: %v", err)
	}
}
