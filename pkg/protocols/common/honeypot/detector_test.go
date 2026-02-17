package honeypot

import "testing"

func TestDetectHoneypot_KnownMarker(t *testing.T) {
	server := "cowrie"
	body := ""

	if !Detect(server, body) {
		t.Fatalf("expected honeypot detection for server=%q body=%q", server, body)
	}
}

func TestDetectHoneypot_Negative(t *testing.T) {
	server := "nginx"
	body := "<html><title>OK</title></html>"

	if Detect(server, body) {
		t.Fatalf("did not expect honeypot detection for server=%q body=%q", server, body)
	}
}
