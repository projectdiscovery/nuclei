package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
