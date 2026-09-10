package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alitto/pond"
	"github.com/projectdiscovery/nuclei/v3/internal/server/scope"
	"github.com/stretchr/testify/require"
)

func TestDASTServerTokenAuthRejectsMissingAndInvalidTokens(t *testing.T) {
	server := &DASTServer{options: &Options{Token: "secret"}}
	server.setupHandlers(false)

	tests := []struct {
		name       string
		target     string
		statusCode int
	}{
		{
			name:       "missing token",
			target:     "/stats",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "invalid token",
			target:     "/stats?token=wrong",
			statusCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, tt.target, nil)
			response := httptest.NewRecorder()

			server.httpServer.Handler.ServeHTTP(response, request)

			require.Equal(t, tt.statusCode, response.Code)
		})
	}
}

func TestDASTServerCORSPreflightBypassesTokenAuth(t *testing.T) {
	server := &DASTServer{options: &Options{Token: "secret"}}
	server.setupHandlers(false)

	request := httptest.NewRequest(http.MethodOptions, "/stats", nil)
	request.Header.Set("Origin", "https://example.com")
	request.Header.Set("Access-Control-Request-Headers", "X-Test")
	response := httptest.NewRecorder()

	server.httpServer.Handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusNoContent, response.Code)
	require.Equal(t, "*", response.Header().Get("Access-Control-Allow-Origin"))
	require.Equal(t, "GET,HEAD,PUT,PATCH,POST,DELETE", response.Header().Get("Access-Control-Allow-Methods"))
	require.Equal(t, "X-Test", response.Header().Get("Access-Control-Allow-Headers"))
}

func TestStatsServerCloseDoesNotRequireFullExecutorOptions(t *testing.T) {
	server, err := NewStatsServer(nil)
	require.NoError(t, err)

	require.NotPanics(t, server.Close)
}

func TestShouldInterceptOnlySkipsExplicitlyExcludedHosts(t *testing.T) {
	scopeManager, err := scope.NewManager(
		// An in-scope rule carrying a path can never match a CONNECT host, so
		// it must not be what decides whether the tunnel is decrypted.
		[]string{`^https://app\.example\.com/api/`},
		[]string{`^https://telemetry\.example\.com/`},
	)
	require.NoError(t, err)
	server := &DASTServer{options: &Options{}, scopeManager: scopeManager}

	require.True(t, server.shouldIntercept("app.example.com:443"))
	require.True(t, server.shouldIntercept("unrelated.example.com:443"))
	require.False(t, server.shouldIntercept("telemetry.example.com:443"))

	// A non-default port stays in the URL, matching what the same rules see
	// once a request off that connection is captured.
	staging, err := scope.NewManager(nil, []string{`^https://staging\.example\.com:8443/`})
	require.NoError(t, err)
	server.scopeManager = staging
	require.False(t, server.shouldIntercept("staging.example.com:8443"))
	require.True(t, server.shouldIntercept("staging.example.com:443"))
}

func TestSubmitDropsInsteadOfBlockingWhenQueueIsFull(t *testing.T) {
	occupied, release := make(chan struct{}), make(chan struct{})

	// One worker and no queue slot: once the worker is busy there is nowhere
	// left for a task to go.
	server := &DASTServer{options: &Options{}, tasksPool: pond.New(1, 0)}
	server.tasksPool.Submit(func() {
		close(occupied)
		<-release
	})
	<-occupied
	defer close(release)

	require.False(t, server.Submit("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "http://example.com/"),
		"a saturated queue must drop rather than block live proxy traffic")
	require.Zero(t, server.endpointsInQueue.Load(), "a dropped request must not stay counted as queued")
}
