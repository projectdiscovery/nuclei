package core

import (
	"context"
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
	// Honeypot: returns 200 for everything
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
