package httpapi

// Tests that the /api/concurrency endpoint requires a valid Bearer token and
// rejects unauthenticated requests with 401 Unauthorized.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/stretchr/testify/require"
)

func newTestServer() *Server {
	return New("127.0.0.1:0", &types.Options{
		BulkSize:          10,
		TemplateThreads:   5,
		RateLimit:         150,
		RateLimitDuration: time.Second,
	})
}

// TestGetWithoutTokenReturns401 verifies that an unauthenticated GET is rejected.
func TestGetWithoutTokenReturns401(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/concurrency", nil)
	w := httptest.NewRecorder()
	s.handleConcurrency(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code,
		"GET /api/concurrency without token must return 401")
}

// TestPutWithoutTokenReturns401 verifies that an unauthenticated PUT is rejected.
func TestPutWithoutTokenReturns401(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPut, "/api/concurrency",
		strings.NewReader(`{"bulk_size":999}`))
	w := httptest.NewRecorder()
	s.handleConcurrency(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code,
		"PUT /api/concurrency without token must return 401")
}

// TestGetWithWrongTokenReturns401 verifies that a wrong token is rejected.
func TestGetWithWrongTokenReturns401(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/concurrency", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()
	s.handleConcurrency(w, req)
	require.Equal(t, http.StatusUnauthorized, w.Code,
		"GET /api/concurrency with wrong token must return 401")
}

// TestGetWithCorrectTokenReturns200 verifies that a correct Bearer token allows access.
func TestGetWithCorrectTokenReturns200(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/api/concurrency", nil)
	req.Header.Set("Authorization", "Bearer "+s.Token())
	w := httptest.NewRecorder()
	s.handleConcurrency(w, req)
	require.Equal(t, http.StatusOK, w.Code,
		"GET /api/concurrency with valid token must return 200")
	require.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

// TestPutWithCorrectTokenModifiesSettings verifies a valid PUT is applied.
func TestPutWithCorrectTokenModifiesSettings(t *testing.T) {
	s := newTestServer()
	req := httptest.NewRequest(http.MethodPut, "/api/concurrency",
		strings.NewReader(`{"bulk_size":42}`))
	req.Header.Set("Authorization", "Bearer "+s.Token())
	w := httptest.NewRecorder()
	s.handleConcurrency(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, 42, s.config.BulkSize)
}

// TestTokenIsNotEmpty verifies that every Server is initialised with a non-empty token.
func TestTokenIsNotEmpty(t *testing.T) {
	s := newTestServer()
	require.NotEmpty(t, s.Token(), "API server token must not be empty")
}

// TestTokensAreUnique verifies that two servers get different tokens.
func TestTokensAreUnique(t *testing.T) {
	s1 := newTestServer()
	s2 := newTestServer()
	require.NotEqual(t, s1.Token(), s2.Token(),
		"Each server instance must have a unique token")
}
