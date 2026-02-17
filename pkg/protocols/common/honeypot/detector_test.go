package honeypot

import "testing"

func TestDetectHoneypot_KnownMarker(t *testing.T) {
	server := "Cowrie" // mixed case to ensure lowercasing works
	body := ""

	if !Detect(server, body) {
		t.Fatalf("expected honeypot detection for server=%q body=%q", server, body)
	}
}

func TestDetectHoneypot_Negative(t *testing.T) {
	server := "nginx"
	body := "<html>ok</html>"

	if Detect(server, body) {
		t.Fatalf("did not expect honeypot detection for server=%q body=%q", server, body)
	}
}
