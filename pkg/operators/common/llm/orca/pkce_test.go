package orca

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeAuth is a stand-in for the OrcaRouter auth origin. It records what it was
// asked and can be told to fail in each documented way.
type fakeAuth struct {
	server *httptest.Server

	// exchangePath records the path each exchange request arrived on, so a test
	// can prove the request did not go to the inference origin's /v1/auth/keys.
	exchangePath string
	// exchangeBody records the decoded exchange body.
	exchangeBody map[string]string
	// challengeSeen is the code_challenge from the authorize url the client
	// opened.
	challengeSeen string
	// appNameSeen is the app_name from the authorize url.
	appNameSeen string
	// callbackSeen is the callback_url from the authorize url.
	callbackSeen string
	// scopeSeen is the scope requested at authorize time.
	scopeSeen string

	// status is the status to answer the exchange with.
	status int
	// body is the raw body to answer with.
	body string
	// code is the only code the server will redeem. Empty accepts any.
	code string
	// issueKey is the key returned on success.
	issueKey string
	// issueScope is the granted scope.
	issueScope string
	// issued counts how many keys were issued, so a test can prove reuse
	// instead of re-authorization.
	issued int
	// exchangeRequests counts exchange calls.
	exchangeRequests int
}

func newFakeAuth(t *testing.T) *fakeAuth {
	t.Helper()

	fake := &fakeAuth{
		status:     http.StatusOK,
		code:       "one-time-code",
		issueKey:   "sk-orca-testkey0123456789abcdef",
		issueScope: ScopeAPI,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(ExchangePath, func(writer http.ResponseWriter, request *http.Request) {
		fake.exchangeRequests++
		fake.exchangePath = request.URL.Path

		raw, _ := io.ReadAll(io.LimitReader(request.Body, 64<<10))
		body := map[string]string{}
		if strings.HasPrefix(request.Header.Get("Content-Type"), "application/json") {
			_ = json.Unmarshal(raw, &body)
		} else {
			values, _ := url.ParseQuery(string(raw))
			for key := range values {
				body[key] = values.Get(key)
			}
		}
		fake.exchangeBody = body

		if fake.status != http.StatusOK {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(fake.status)
			_, _ = io.WriteString(writer, fake.body)

			return
		}

		// The verifier must hash to the challenge sent at authorize time. This
		// is the property that makes an intercepted code useless.
		if CodeChallenge(body["code_verifier"]) != fake.challengeSeen {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(writer, `{"error":"invalid_grant"}`)

			return
		}
		if body["code_challenge_method"] != CodeChallengeMethod {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(writer, `{"error":"invalid_request"}`)

			return
		}
		if fake.code != "" && body["code"] != fake.code {
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusForbidden)
			_, _ = io.WriteString(writer, `{"error":"invalid_grant","error_description":"code unknown"}`)

			return
		}

		fake.issued++
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(ExchangeResult{
			Key:    fake.issueKey,
			UserID: "12345",
			Scope:  fake.issueScope,
		})
	})

	fake.server = httptest.NewServer(mux)
	t.Cleanup(fake.server.Close)

	return fake
}

// endpoints points the client at the fake auth origin and a separate fake
// inference origin, which is what lets a test prove the two never swap.
func (f *fakeAuth) endpoints(t *testing.T, apiBase string) Endpoints {
	t.Helper()

	return Endpoints{Auth: f.server.URL, API: apiBase}
}

// browser performs what a real browser would: it reads the authorize url the
// client announced, then delivers the redirect to the callback it named.
func (f *fakeAuth) browser(t *testing.T, code, stateOverride string) func(string) error {
	t.Helper()

	return func(authorizeURL string) error {
		parsed, err := url.Parse(authorizeURL)
		if err != nil {
			return err
		}

		query := parsed.Query()
		f.challengeSeen = query.Get("code_challenge")
		f.appNameSeen = query.Get("app_name")
		f.callbackSeen = query.Get("callback_url")
		f.scopeSeen = query.Get("scope")

		if f.callbackSeen == CallbackURLOutOfBand {
			return nil
		}

		state := query.Get("state")
		if stateOverride != "" {
			state = stateOverride
		}

		redirect := f.callbackSeen + "?state=" + url.QueryEscape(state)
		if code != "" {
			redirect += "&code=" + url.QueryEscape(code)
		}

		go func() {
			response, err := http.Get(redirect) //nolint:gosec // loopback test listener
			if err == nil {
				_ = response.Body.Close()
			}
		}()

		return nil
	}
}

// TestPKCEMaterialIsFreshAndHashed proves the verifier is unpredictable per
// attempt and that only its S256 hash leaves the process.
func TestPKCEMaterialIsFreshAndHashed(t *testing.T) {
	first, err := NewPKCE()
	require.NoError(t, err)
	second, err := NewPKCE()
	require.NoError(t, err)

	require.NotEqual(t, first.Verifier, second.Verifier, "verifier must be fresh per attempt")
	require.NotEqual(t, first.State, second.State, "state must be fresh per attempt")
	require.NotEqual(t, first.Challenge, second.Challenge)

	// The challenge is the unpadded base64url sha256 of the verifier.
	require.Equal(t, CodeChallenge(first.Verifier), first.Challenge)
	require.NotContains(t, first.Challenge, "=", "challenge must be unpadded")
	require.NotContains(t, first.Challenge, "+")
	require.NotContains(t, first.Challenge, "/")

	// 32 random bytes base64url encoded is 43 characters.
	require.Len(t, first.Verifier, 43)
	require.NotEqual(t, first.Verifier, first.Challenge, "the verifier must never be the challenge")

	_, err = base64.RawURLEncoding.DecodeString(first.Verifier)
	require.NoError(t, err)
}

// TestMatchesStateIsConstantTimeComparison proves the state check accepts only
// the exact value.
func TestMatchesStateIsConstantTimeComparison(t *testing.T) {
	pkce, err := NewPKCE()
	require.NoError(t, err)

	require.True(t, pkce.MatchesState(pkce.State))
	require.False(t, pkce.MatchesState(""))
	require.False(t, pkce.MatchesState(pkce.State+"x"))
	require.False(t, pkce.MatchesState(strings.ToUpper(pkce.State)))
}

// TestAuthorizeURLCarriesOnlyTheChallenge proves the verifier never rides on the
// authorize url, which is what travels through browser history and proxies.
func TestAuthorizeURLCarriesOnlyTheChallenge(t *testing.T) {
	pkce, err := NewPKCE()
	require.NoError(t, err)

	authorize := AuthorizeURL("https://www.orcarouter.ai", "oob", pkce, "nuclei", ScopeAPI)

	require.NotContains(t, authorize, pkce.Verifier, "the verifier must not appear in the authorize url")
	require.Contains(t, authorize, "code_challenge="+pkce.Challenge)
	require.Contains(t, authorize, "code_challenge_method=S256")
	require.Contains(t, authorize, "callback_url=oob")
	require.Contains(t, authorize, "app_name=nuclei")
	require.Contains(t, authorize, "scope=api")
	require.True(t, strings.HasPrefix(authorize, "https://www.orcarouter.ai/auth?"))
}

// TestExchangeUsesAuthOriginAndDocumentedBody proves the exchange goes to
// /api/v1/auth/keys on the auth origin with the documented JSON body.
func TestExchangeUsesAuthOriginAndDocumentedBody(t *testing.T) {
	fake := newFakeAuth(t)
	pkce, err := NewPKCE()
	require.NoError(t, err)
	fake.challengeSeen = pkce.Challenge

	result, err := Exchange(t.Context(), fake.server.Client(), fake.server.URL, "one-time-code", pkce.Verifier)
	require.NoError(t, err)
	require.Equal(t, fake.issueKey, result.Key)
	require.Equal(t, "12345", result.UserID)
	require.Equal(t, ScopeAPI, result.Scope)

	require.Equal(t, "/api/v1/auth/keys", fake.exchangePath)
	require.NotEqual(t, "/v1/auth/keys", fake.exchangePath)
	require.Equal(t, "one-time-code", fake.exchangeBody["code"])
	require.Equal(t, pkce.Verifier, fake.exchangeBody["code_verifier"])
	require.Equal(t, CodeChallengeMethod, fake.exchangeBody["code_challenge_method"])
}

// TestExchangeClassifiesFailures proves each documented failure is terminal and
// typed, rather than a retry or a hang.
func TestExchangeClassifiesFailures(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		expected PKCEErrorKind
	}{
		{"rejected code", http.StatusForbidden, `{"error":"invalid_grant"}`, PKCEErrorRejected},
		{"method downgrade", http.StatusBadRequest, `{"error":"invalid_request"}`, PKCEErrorMethodDowngrade},
		{"rate limited", http.StatusTooManyRequests, `{"error":"too_many_requests"}`, PKCEErrorRateLimited},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			fake := newFakeAuth(t)
			fake.status = testCase.status
			fake.body = testCase.body

			pkce, err := NewPKCE()
			require.NoError(t, err)
			fake.challengeSeen = pkce.Challenge

			_, err = Exchange(t.Context(), fake.server.Client(), fake.server.URL, "one-time-code", pkce.Verifier)
			require.Error(t, err)

			var typed *PKCEError
			require.True(t, errors.As(err, &typed))
			require.Equal(t, testCase.expected, typed.Kind)
			require.NotContains(t, err.Error(), pkce.Verifier, "an error must never carry the verifier")
			require.NotContains(t, err.Error(), "sk-orca-", "an error must never carry a key")
		})
	}
}

// TestExchangeRejectsScopeDowngrade proves a narrower grant is reported instead
// of assumed sufficient.
func TestExchangeRejectsScopeDowngrade(t *testing.T) {
	fake := newFakeAuth(t)
	fake.issueScope = "connector"

	pkce, err := NewPKCE()
	require.NoError(t, err)
	fake.challengeSeen = pkce.Challenge

	_, err = Exchange(t.Context(), fake.server.Client(), fake.server.URL, "one-time-code", pkce.Verifier)
	require.Error(t, err)

	var typed *PKCEError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, PKCEErrorScopeDowngrade, typed.Kind)
	require.Contains(t, err.Error(), "connector")
}

// TestExchangeNetworkFailureIsTyped proves an unreachable auth origin is a
// bounded error rather than a hot loop.
func TestExchangeNetworkFailureIsTyped(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	origin := server.URL
	server.Close()

	pkce, err := NewPKCE()
	require.NoError(t, err)

	_, err = Exchange(t.Context(), server.Client(), origin, "code", pkce.Verifier)
	require.Error(t, err)

	var typed *PKCEError
	require.True(t, errors.As(err, &typed))
	require.Equal(t, PKCEErrorNetwork, typed.Kind)
	require.NotContains(t, err.Error(), pkce.Verifier)
}
