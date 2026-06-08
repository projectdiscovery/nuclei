package authx

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeAuthServer simulates a login + protected-resource backend with
// server-side session expiry, to exercise the dynamic session lifecycle end to
// end over real HTTP:
//   - GET /login issues a fresh incrementing bearer token and marks it as the
//     only currently-valid session.
//   - GET /api returns 200 when the presented bearer matches the valid session,
//     and 401 once the session has been expired server-side.
type fakeAuthServer struct {
	mu      sync.Mutex
	counter int
	valid   string // currently valid token; empty means "no valid session"
	logins  atomic.Int32
}

func (s *fakeAuthServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.counter++
		s.valid = fmt.Sprintf("sess-%d", s.counter)
		tok := s.valid
		s.mu.Unlock()
		s.logins.Add(1)
		_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		valid := s.valid
		s.mu.Unlock()
		if valid != "" && r.Header.Get("Authorization") == "Bearer "+valid {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "secret-data")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "session expired")
	})
	return mux
}

// expire invalidates the current session server-side without issuing a new one,
// so the next /api call with the old token returns 401.
func (s *fakeAuthServer) expire() {
	s.mu.Lock()
	s.valid = ""
	s.mu.Unlock()
}

// TestSessionLifecycle_E2E drives the whole dynamic-session state machine against
// a real HTTP server: it performs a real login to mint a token, uses it on a
// protected endpoint, lets the server expire the session, and verifies that a
// 401 (surfaced through NotifyResponse) triggers a real re-authentication whose
// fresh token restores access — all through the production Dynamic/strategy code.
func TestSessionLifecycle_E2E(t *testing.T) {
	backend := &fakeAuthServer{}
	srv := httptest.NewServer(backend.handler())
	defer srv.Close()

	httpClient := srv.Client()

	d := &Dynamic{
		Secret: &Secret{
			Type:    "Header",
			Domains: []string{"127.0.0.1", "localhost"},
			Headers: []KV{{Key: "Authorization", Value: "Bearer {{token}}"}},
		},
		TemplatePath:      "auth.yaml",
		Variables:         []KV{{Key: "user", Value: "admin"}},
		ReauthStatusCodes: []int{401},
	}
	require.NoError(t, d.Validate())

	// The login callback performs a REAL HTTP login and extracts the token, the
	// same shape the template-driven fetch produces.
	d.SetLazyFetchCallback(func(dyn *Dynamic) error {
		resp, err := httpClient.Get(srv.URL + "/login")
		if err != nil {
			return err
		}
		defer func() { _ = resp.Body.Close() }()
		var payload struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
			return err
		}
		dyn.Extracted = map[string]interface{}{"token": payload.Token}
		return nil
	})

	strat := &DynamicAuthStrategy{Dynamic: *d}
	inspector, ok := AuthStrategy(strat).(ResponseInspector)
	require.True(t, ok, "DynamicAuthStrategy must implement ResponseInspector")

	// doAPI applies the (possibly re-authenticated) session and calls /api.
	doAPI := func() int {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/api", nil)
		require.NoError(t, err)
		strat.Apply(req)
		resp, err := httpClient.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		// surface the response to the auth strategy, like the http protocol does
		inspector.OnResponse(resp.StatusCode)
		return resp.StatusCode
	}

	// 1) First call logs in and succeeds.
	require.Equal(t, http.StatusOK, doAPI(), "first authenticated request should succeed")
	require.Equal(t, int32(1), backend.logins.Load(), "exactly one login so far")
	require.False(t, d.IsExpired())

	// 2) Server expires the session out from under us → next call sees 401 and,
	// via NotifyResponse, marks the session stale.
	backend.expire()
	require.Equal(t, http.StatusUnauthorized, doAPI(), "request with the now-expired token should 401")
	require.True(t, d.IsExpired(), "401 must mark the session stale for re-authentication")

	// 3) Next call re-authenticates (a second real login) and succeeds again.
	require.Equal(t, http.StatusOK, doAPI(), "request after re-auth should succeed with the fresh token")
	require.Equal(t, int32(2), backend.logins.Load(), "a second login should have occurred")
	require.False(t, d.IsExpired(), "session should be fresh again after re-auth")
}
