package authx

import (
	"net/http"

	"github.com/projectdiscovery/retryablehttp-go"
)

var (
	_ AuthStrategy           = &WebStorageAuthStrategy{}
	_ BrowserStorageProvider = &WebStorageAuthStrategy{}
)

// BrowserStorageProvider is an optional interface implemented by auth strategies
// that carry browser web storage (localStorage/sessionStorage) to be replayed
// into headless scan pages. HTTP-only strategies do not implement it, so the
// headless engine type-asserts for it before seeding storage.
type BrowserStorageProvider interface {
	// WebStorage returns the localStorage and sessionStorage items to seed.
	WebStorage() (local map[string]string, session map[string]string)
}

// WebStorageAuthStrategy carries captured web storage. Its Apply methods are
// intentional no-ops: web storage cannot be expressed on an HTTP request, so it
// only takes effect in the headless engine, which reads it via the
// BrowserStorageProvider interface and seeds it into the page before page
// scripts run.
type WebStorageAuthStrategy struct {
	Local   map[string]string
	Session map[string]string
}

// NewWebStorageAuthStrategy creates a new web storage auth strategy.
func NewWebStorageAuthStrategy(local, session map[string]string) *WebStorageAuthStrategy {
	return &WebStorageAuthStrategy{Local: local, Session: session}
}

// Apply is a no-op (web storage is not an HTTP request artifact).
func (s *WebStorageAuthStrategy) Apply(_ *http.Request) {}

// ApplyOnRR is a no-op (web storage is not an HTTP request artifact).
func (s *WebStorageAuthStrategy) ApplyOnRR(_ *retryablehttp.Request) {}

// WebStorage returns the carried storage items.
func (s *WebStorageAuthStrategy) WebStorage() (map[string]string, map[string]string) {
	return s.Local, s.Session
}
