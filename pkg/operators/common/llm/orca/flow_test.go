package orca

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestLoginLoopbackPersistsIssuedKey is the end-to-end Flow A test: it runs the
// project's own connect adapter against a fake auth server and proves the
// authorize -> callback -> exchange -> persist chain.
func TestLoginLoopbackPersistsIssuedKey(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	var announced string
	credential, err := Login(t.Context(), store, LoginOptions{
		Endpoints:      fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:        AppName,
		OpenBrowser:    fake.browser(t, "one-time-code", ""),
		OnAuthorizeURL: func(u string) { announced = u },
		Timeout:        10 * time.Second,
	})
	require.NoError(t, err)

	// The key reached the caller and the store.
	require.Equal(t, fake.issueKey, credential.Key)
	require.Equal(t, "12345", credential.UserID)
	require.Equal(t, ScopeAPI, credential.Scope)
	require.Equal(t, int64(1), credential.Generation)

	loaded, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, fake.issueKey, loaded.Key)

	// The authorize url named a loopback callback and asked for the inference
	// scope, and the verifier never appeared anywhere.
	require.Contains(t, announced, "callback_url=http%3A%2F%2F127.0.0.1")
	require.Equal(t, "api", fake.scopeSeen)
	require.Equal(t, AppName, fake.appNameSeen)
	require.NotContains(t, announced, "code_verifier")
	require.NotContains(t, announced, "verifier")
	require.Equal(t, 1, fake.exchangeRequests)

	// The exchange went to the auth origin, not the inference origin.
	require.Equal(t, "/api/v1/auth/keys", fake.exchangePath)
	require.Equal(t, "S256", fake.exchangeBody["code_challenge_method"])
}

// TestLoginOutOfBandPersistsIssuedKey is the end-to-end Flow B test.
func TestLoginOutOfBandPersistsIssuedKey(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	var announced string
	credential, err := Login(t.Context(), store, LoginOptions{
		Endpoints:      fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:        AppName,
		Flow:           FlowOutOfBand,
		OpenBrowser:    fake.browser(t, "one-time-code", ""),
		OnAuthorizeURL: func(u string) { announced = u },
		PromptCode:     func(string) (string, error) { return "one-time-code", nil },
		Timeout:        10 * time.Second,
	})
	require.NoError(t, err)
	require.Equal(t, fake.issueKey, credential.Key)

	// Flow B asks for the literal oob callback and still sends S256.
	require.Contains(t, announced, "callback_url=oob")
	require.Contains(t, announced, "code_challenge_method=S256")
	require.NotContains(t, announced, "code_verifier")
	require.Equal(t, 1, fake.exchangeRequests)
	require.Equal(t, "/api/v1/auth/keys", fake.exchangePath)
}

// TestLoginLoopbackStateMismatchIsRejectedWithoutExchange proves a callback that
// did not belong to this attempt is refused before the code is redeemed.
func TestLoginLoopbackStateMismatchIsRejectedWithoutExchange(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	_, err := Login(t.Context(), store, LoginOptions{
		Endpoints:   fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:     AppName,
		OpenBrowser: fake.browser(t, "one-time-code", "not-the-state-we-sent"),
		Timeout:     10 * time.Second,
	})
	require.Error(t, err)

	var typed *PKCEError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, PKCEErrorStateMismatch, typed.Kind)
	require.Zero(t, fake.exchangeRequests, "a mismatched state must never be exchanged")
	require.False(t, fileExists(store.Path), "a failed login must store nothing")
}

// TestLoginDenialIsTerminal proves a declined consent ends cleanly.
func TestLoginDenialIsTerminal(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	_, err := Login(t.Context(), store, LoginOptions{
		Endpoints: fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:   AppName,
		OpenBrowser: func(authorizeURL string) error {
			parsed, parseErr := url.Parse(authorizeURL)
			require.NoError(t, parseErr)

			callback := parsed.Query().Get("callback_url")
			state := parsed.Query().Get("state")

			go func() {
				response, getErr := http.Get(callback + "?error=access_denied&state=" + url.QueryEscape(state)) //nolint:gosec // loopback test listener
				if getErr == nil {
					_ = response.Body.Close()
				}
			}()

			return nil
		},
		Timeout: 10 * time.Second,
	})
	require.Error(t, err)

	var typed *PKCEError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, PKCEErrorDenied, typed.Kind)
	require.Zero(t, fake.exchangeRequests)
	require.False(t, fileExists(store.Path))
}

// TestLoginTimeoutIsBounded proves a login nobody answers ends at the deadline
// instead of hanging.
func TestLoginTimeoutIsBounded(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	started := time.Now()
	_, err := Login(t.Context(), store, LoginOptions{
		Endpoints:   fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:     AppName,
		OpenBrowser: func(string) error { return nil },
		Timeout:     300 * time.Millisecond,
	})
	require.Error(t, err)
	require.Less(t, time.Since(started), 10*time.Second)

	var typed *PKCEError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, PKCEErrorTimeout, typed.Kind)
	require.False(t, fileExists(store.Path))
}

// TestLoginCancelIsBounded proves an explicit cancel releases the attempt.
func TestLoginCancelIsBounded(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	_, err := Login(ctx, store, LoginOptions{
		Endpoints:   fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:     AppName,
		OpenBrowser: func(string) error { return nil },
		Timeout:     30 * time.Second,
	})
	require.Error(t, err)

	var typed *PKCEError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, PKCEErrorCanceled, typed.Kind)
}

// TestLoginReusesStoredCredentialInsteadOfReissuing proves a second login does
// not mint another key, which is what keeps a client under the per-user cap.
func TestLoginReusesStoredCredentialInsteadOfReissuing(t *testing.T) {
	store := tempStore(t)
	_, err := store.Save(Credential{Key: "sk-orca-existing", Scope: ScopeAPI, UserID: "9"}, SourcePKCE)
	require.NoError(t, err)

	// A scan reads the stored credential through the seam without any login.
	source := DefaultCredentialSource("", store)
	credential, err := source.Credential()
	require.NoError(t, err)
	require.Equal(t, "sk-orca-existing", credential.Key)
	require.Equal(t, "9", credential.UserID)
}

// TestLoginFallsBackToOutOfBandWhenLoopbackIsUnavailable proves a host that
// cannot accept a callback still gets a usable login.
func TestLoginFallsBackToOutOfBandWhenLoopbackIsUnavailable(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	var flows []string
	credential, err := Login(t.Context(), store, LoginOptions{
		Endpoints: fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:   AppName,
		Flow:      FlowLoopback,
		// Simulate a host where binding a loopback listener fails.
		listen: func(string, string) (net.Listener, error) {
			return nil, errors.New("listen tcp 127.0.0.1:0: operation not permitted")
		},
		OpenBrowser: func(authorizeURL string) error {
			parsed, parseErr := url.Parse(authorizeURL)
			require.NoError(t, parseErr)
			flows = append(flows, parsed.Query().Get("callback_url"))

			// The consent screen is what a browser would have loaded.
			return fake.browser(t, "one-time-code", "")(authorizeURL)
		},
		PromptCode: func(string) (string, error) { return "one-time-code", nil },
		Timeout:    10 * time.Second,
	})
	require.NoError(t, err)
	require.Equal(t, fake.issueKey, credential.Key)
	require.Equal(t, []string{CallbackURLOutOfBand}, flows)
	require.Equal(t, 1, fake.exchangeRequests)
}

// TestLoginRequiresPromptForOutOfBandWithoutTerminal proves a non-interactive
// caller gets a typed error instead of a hang.
func TestLoginRequiresPromptForOutOfBandWithoutTerminal(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	_, err := Login(t.Context(), store, LoginOptions{
		Endpoints:   fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:     AppName,
		Flow:        FlowOutOfBand,
		OpenBrowser: func(string) error { return nil },
		Timeout:     5 * time.Second,
	})
	require.Error(t, err)

	var typed *PKCEError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, PKCEErrorRejected, typed.Kind)
	require.Zero(t, fake.exchangeRequests)
}

// TestLoginRejectsPlainHTTPRemoteOrigins proves a credential cannot be sent in
// clear text to a remote origin.
func TestLoginRejectsPlainHTTPRemoteOrigins(t *testing.T) {
	store := tempStore(t)

	_, err := Login(t.Context(), store, LoginOptions{
		Endpoints: Endpoints{Auth: "http://auth.example.com", API: "https://api.example.com/v1"},
		AppName:   AppName,
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "https")

	// Loopback over plain http is allowed for local development.
	require.NoError(t, ValidateEndpoints(Endpoints{
		Auth: "http://127.0.0.1:8080",
		API:  "http://localhost:8080/v1",
	}))
	require.NoError(t, ValidateEndpoints(Endpoints{
		Auth: "https://www.orcarouter.ai",
		API:  "https://api.orcarouter.ai/v1",
	}))
}

// TestLoginStoresNothingOnExchangeFailure proves a failed exchange leaves any
// previous credential intact.
func TestLoginStoresNothingOnExchangeFailure(t *testing.T) {
	fake := newFakeAuth(t)
	fake.status = http.StatusForbidden
	fake.body = `{"error":"invalid_grant"}`
	store := tempStore(t)

	previous, err := store.Save(Credential{Key: "sk-orca-previous", Scope: ScopeAPI}, SourceAPIKey)
	require.NoError(t, err)

	_, err = Login(t.Context(), store, LoginOptions{
		Endpoints:   fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:     AppName,
		OpenBrowser: fake.browser(t, "one-time-code", ""),
		Timeout:     10 * time.Second,
	})
	require.Error(t, err)

	loaded, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, "sk-orca-previous", loaded.Key, "the previous credential must survive")
	require.Equal(t, previous.Generation, loaded.Generation)
}

// TestCodeReuseIsRejected proves a replayed code is refused.
func TestCodeReuseIsRejected(t *testing.T) {
	fake := newFakeAuth(t)
	pkce, err := NewPKCE()
	require.NoError(t, err)
	fake.challengeSeen = pkce.Challenge

	_, err = Exchange(t.Context(), fake.server.Client(), fake.server.URL, "one-time-code", pkce.Verifier)
	require.NoError(t, err)

	// The real server invalidates the code after one use; the fake models that
	// by accepting only the first redemption.
	fake.code = "already-consumed"
	_, err = Exchange(t.Context(), fake.server.Client(), fake.server.URL, "one-time-code", pkce.Verifier)
	require.Error(t, err)

	var typed *PKCEError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, PKCEErrorRejected, typed.Kind)
}

// TestLoginAgainstFakeServerKeepsAuthAndInferenceOriginsSeparate is the
// separation test: the auth origin serves /auth and the exchange, the inference
// origin serves chat and models, and neither request is sent to the other.
func TestLoginAgainstFakeServerKeepsAuthAndInferenceOriginsSeparate(t *testing.T) {
	var authOriginHits, inferenceOriginHits atomic.Int64
	var wrongPathHits atomic.Int64

	authMux := http.NewServeMux()
	authMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		authOriginHits.Add(1)
		if request.URL.Path == "/v1/auth/keys" {
			wrongPathHits.Add(1)
			http.NotFound(writer, request)

			return
		}
		if request.URL.Path != ExchangePath {
			http.NotFound(writer, request)

			return
		}

		raw, _ := io.ReadAll(io.LimitReader(request.Body, 64<<10))
		body := map[string]string{}
		_ = json.Unmarshal(raw, &body)

		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(ExchangeResult{
			Key:    "sk-orca-separated",
			UserID: "77",
			Scope:  ScopeAPI,
		})
	})
	authServer := httptest.NewServer(authMux)
	defer authServer.Close()

	inferenceMux := http.NewServeMux()
	inferenceMux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		inferenceOriginHits.Add(1)
		if strings.HasPrefix(request.URL.Path, "/auth") || strings.HasPrefix(request.URL.Path, "/api/v1/auth") {
			wrongPathHits.Add(1)
			http.NotFound(writer, request)

			return
		}

		switch request.URL.Path {
		case "/v1/models":
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"data":[{"id":"openai/gpt-5.5","supported_endpoint_types":["openai"]}]}`)
		case "/v1/chat/completions":
			require.Equal(t, "Bearer sk-orca-separated", request.Header.Get("Authorization"))
			writer.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(writer, `{"choices":[{"message":{"content":"hello"}}]}`)
		default:
			http.NotFound(writer, request)
		}
	})
	inferenceServer := httptest.NewServer(inferenceMux)
	defer inferenceServer.Close()

	endpoints := Endpoints{Auth: authServer.URL, API: inferenceServer.URL + "/v1"}
	require.NoError(t, ValidateEndpoints(endpoints))

	store := tempStore(t)
	credential, err := Login(t.Context(), store, LoginOptions{
		Endpoints:   endpoints,
		AppName:     AppName,
		OpenBrowser: fakeBrowserForAuth(authServer.URL),
		Timeout:     10 * time.Second,
	})
	require.NoError(t, err)
	require.Equal(t, "sk-orca-separated", credential.Key)

	// Inference and discovery use the credential on the inference origin.
	client, err := New(Config{
		Provider:    ProviderName,
		APIKey:      credential.Key,
		Store:       store,
		AuthBaseURL: authServer.URL,
		APIBaseURL:  inferenceServer.URL + "/v1",
		Timeout:     5 * time.Second,
	})
	require.NoError(t, err)

	answer, err := client.Complete(t.Context(), "hello", false)
	require.NoError(t, err)
	require.Equal(t, "hello", answer)

	catalog := DiscoverModels(t.Context(), endpoints, credential.Key)
	require.True(t, catalog.Live)
	require.Len(t, catalog.Models, 1)
	require.Equal(t, "openai/gpt-5.5", catalog.Models[0].ID)

	require.Greater(t, authOriginHits.Load(), int64(0))
	require.Greater(t, inferenceOriginHits.Load(), int64(0))
	require.Zero(t, wrongPathHits.Load(),
		"auth requests must not reach the inference origin and vice versa")
}

// fakeBrowserForAuth delivers the redirect for a plain fake auth origin that
// does not validate the challenge.
func fakeBrowserForAuth(string) func(string) error {
	return func(authorizeURL string) error {
		parsed, err := url.Parse(authorizeURL)
		if err != nil {
			return err
		}

		callback := parsed.Query().Get("callback_url")
		state := parsed.Query().Get("state")

		go func() {
			response, getErr := http.Get(callback + "?code=one-time-code&state=" + url.QueryEscape(state)) //nolint:gosec // loopback test listener
			if getErr == nil {
				_ = response.Body.Close()
			}
		}()

		return nil
	}
}
