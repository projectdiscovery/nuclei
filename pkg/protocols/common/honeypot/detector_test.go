package honeypot

import "testing"

func TestDetectCowrie(t *testing.T) {
	server := "Cowrie SSH Honeypot"

	if !Detect(server, "") {
		t.Fatal("failed to detect honeypot")
	}
}

func TestDetectNormalServer(t *testing.T) {
	server := "nginx"

	if Detect(server, "") {
		t.Fatal("false positive honeypot detection")
	}
}

