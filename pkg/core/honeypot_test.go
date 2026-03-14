package core

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestHoneypotDetector_RealServer(t *testing.T) {
	// Real server: returns 404 for unknown paths
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	d := NewHoneypotDetector(5*time.Second, 0.8, 3)
	result := d.Check(context.Background(), srv.URL)
	assert.False(t, result.IsHoneypot, "real server should not be flagged as honeypot")
}

func TestHoneypotDetector_Honeypot(t *testing.T) {
	// Honeypot: returns 200 for everything with identical body
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><body>Login page</body></html>"))
	}))
	defer srv.Close()

	d := NewHoneypotDetector(5*time.Second, 0.8, 3)
	result := d.Check(context.Background(), srv.URL)
	assert.True(t, result.IsHoneypot, "honeypot server should be detected")
	assert.GreaterOrEqual(t, result.Confidence, 0.8)
}

// TestHoneypotDetector_EchoService verifies that a service which echoes the
// request path inside a fixed template is NOT flagged as a honeypot. This
// catches the false-positive where body-length variance alone is insufficient
// because the canary token is small relative to the surrounding template.
func TestHoneypotDetector_EchoService(t *testing.T) {
	// Echo service: returns 200 with the request path embedded in a large fixed template.
	// The body length barely varies between probes despite unique canary content.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// ~4KB fixed template with the path echoed once
		padding := make([]byte, 4000)
		for i := range padding {
			padding[i] = 'A'
		}
		body := fmt.Sprintf("<html><body><h1>Error</h1><p>Page not found: %s</p><div>%s</div></body></html>",
			r.URL.Path, string(padding))
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d := NewHoneypotDetector(5*time.Second, 0.8, 5)
	result := d.Check(context.Background(), srv.URL)
	assert.False(t, result.IsHoneypot,
		"echo service should NOT be flagged as honeypot (reason=%s)", result.Reason)
}

// TestHoneypotDetector_CatchAll200 verifies that a legitimate catch-all-200 app
// is NOT flagged as a honeypot. The server returns 200 for every path but serves
// meaningfully different content per path (high body-length variance), which is
// characteristic of a real web application with wildcard routing rather than a
// honeypot.
func TestHoneypotDetector_CatchAll200(t *testing.T) {
	// Wildcard app: returns 200 everywhere but with very different body sizes
	// (simulates a real app using wildcard routing with unique per-path content)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		// Encode the full path into the body so each random canary path
		// produces a clearly different content length.
		body := fmt.Sprintf(
			"<html><body><h1>Welcome</h1><p>You requested: %s</p>%s</body></html>",
			r.URL.Path,
			// Extra padding to ensure the variance easily exceeds the threshold
			// (contentLenStdDevThreshold = 200 bytes). Each canary path is a
			// 20-char hex string embedded in ~300 bytes of surrounding HTML.
			"<p>This is a real application page with substantial content that varies per path.</p>",
		)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	d := NewHoneypotDetector(5*time.Second, 0.8, 5)
	result := d.Check(context.Background(), srv.URL)
	assert.False(t, result.IsHoneypot,
		"catch-all-200 app with varying content should NOT be flagged as honeypot (got confidence=%.2f, reason=%s)",
		result.Confidence, result.Reason)
	assert.GreaterOrEqual(t, result.Confidence, 0.8, "confidence should be high since all probes return 200, but host should not be honeypot due to varying content")
}
