package hostratelimit

import "testing"

func TestNormalizeHostPortWebSocketDefaults(t *testing.T) {
	if got, want := NormalizeHostPort("wss://example.com"), "example.com:443"; got != want {
		t.Fatalf("wss default port: got %q, want %q", got, want)
	}
	if got, want := NormalizeHostPort("https://example.com"), "example.com:443"; got != want {
		t.Fatalf("https default port: got %q, want %q", got, want)
	}
	if got, want := NormalizeHostPort("ws://example.com"), "example.com:80"; got != want {
		t.Fatalf("ws default port: got %q, want %q", got, want)
	}
	if got, want := NormalizeHostPort("wss://example.com:8443/socket"), "example.com:8443"; got != want {
		t.Fatalf("explicit wss port: got %q, want %q", got, want)
	}
}
