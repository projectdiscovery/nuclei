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

func TestDetectHoneypotApache(t *testing.T) {
    server := "Apache/2.4.49"
    body := "Forbidden access"

    result := Detect(server, body)

    require.True(t, result)
}

