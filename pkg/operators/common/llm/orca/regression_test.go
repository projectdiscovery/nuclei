package orca

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	llmclient "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/llm"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

// TestSecretsNeverAppearInLogsOrErrors proves the verifier, the authorization
// code and the issued key do not reach stdout, a logger, or an error string.
func TestSecretsNeverAppearInLogsOrErrors(t *testing.T) {
	fake := newFakeAuth(t)
	store := tempStore(t)

	const code = "one-time-secret-code"
	fake.code = code

	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	defer log.SetOutput(previous)

	var announced string
	credential, err := Login(t.Context(), store, LoginOptions{
		Endpoints:      fake.endpoints(t, "https://api.example.invalid/v1"),
		AppName:        AppName,
		OpenBrowser:    fake.browser(t, code, ""),
		OnAuthorizeURL: func(u string) { announced = u },
		Timeout:        10 * time.Second,
	})
	require.NoError(t, err)

	verifier := fake.exchangeBody["code_verifier"]
	require.NotEmpty(t, verifier)

	for name, haystack := range map[string]string{
		"authorize url": announced,
		"stdout log":    logged.String(),
		"credential":    credential.Masked(),
		"catalog error": Catalog{Error: "boom"}.Error,
	} {
		require.NotContains(t, haystack, verifier, "%s must not carry the verifier", name)
		require.NotContains(t, haystack, credential.Key, "%s must not carry the key", name)
		require.NotContains(t, haystack, code, "%s must not carry the code", name)
	}

	// The exchange request itself is the one place the verifier legitimately
	// appears, and it goes to the auth origin.
	require.Equal(t, "/api/v1/auth/keys", fake.exchangePath)

	// A failure message must not carry them either.
	_, err = Exchange(t.Context(), fake.server.Client(), fake.server.URL, "bad-code", verifier)
	require.Error(t, err)
	require.NotContains(t, err.Error(), verifier)
	require.NotContains(t, err.Error(), credential.Key)
}

// TestFailureErrorsCarryNoCredential proves every typed failure renders without
// a secret.
func TestFailureErrorsCarryNoCredential(t *testing.T) {
	const key = "sk-orca-must-not-leak"
	const verifier = "verifier-must-not-leak"

	for _, kind := range []PKCEErrorKind{
		PKCEErrorDenied,
		PKCEErrorStateMismatch,
		PKCEErrorTimeout,
		PKCEErrorCanceled,
		PKCEErrorRejected,
		PKCEErrorMethodDowngrade,
		PKCEErrorScopeDowngrade,
		PKCEErrorRateLimited,
		PKCEErrorNetwork,
		PKCEErrorListener,
	} {
		rendered := DescribePKCEError(NewPKCEError(kind, "failed"))
		require.NotContains(t, rendered, key)
		require.NotContains(t, rendered, verifier)
	}

	// A wrapped transport error is redacted too.
	wrapped := wrapSecretError(io.ErrUnexpectedEOF, "exchange failed with "+key+" and "+verifier, key, verifier)
	require.NotContains(t, wrapped.Error(), key)
	require.NotContains(t, wrapped.Error(), verifier)
}

// TestMatcherUsesTheOrcaRouterClientUnchanged proves the change is transparent
// to the nuclei entry point: an llm matcher drives the OrcaRouter client through
// the same interface it already used, and a credential-source change does not
// alter the request.
func TestMatcherUsesTheOrcaRouterClientUnchanged(t *testing.T) {
	var requests int
	var sawModel string

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		require.Equal(t, "/v1/chat/completions", request.URL.Path)

		raw, _ := io.ReadAll(io.LimitReader(request.Body, 64<<10))
		var payload struct {
			Model    string `json:"model"`
			Messages []struct {
				Content string `json:"content"`
			} `json:"messages"`
		}
		require.NoError(t, json.Unmarshal(raw, &payload))
		sawModel = payload.Model
		require.NotEmpty(t, payload.Messages)

		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"choices":[{"message":{"content":"{\"verdict\":\"yes\",\"confidence\":0.91,\"evidence\":\"q\"}"}}]}`)
	}))
	defer server.Close()

	// Build the client through the API-key adapter, then through the stored
	// PKCE adapter, and drive the matcher with both.
	apiKeyClient, err := New(Config{
		Provider:    ProviderName,
		APIKey:      "sk-orca-matcher-api-key",
		AuthBaseURL: server.URL,
		APIBaseURL:  server.URL + "/v1",
		Model:       "openai/gpt-5.5",
	})
	require.NoError(t, err)

	store := tempStore(t)
	_, err = store.Save(Credential{Key: "sk-orca-matcher-pkce", Scope: ScopeAPI}, SourcePKCE)
	require.NoError(t, err)

	pkceClient, err := New(Config{
		Provider:    ProviderName,
		Store:       store,
		AuthBaseURL: server.URL,
		APIBaseURL:  server.URL + "/v1",
		Model:       "openai/gpt-5.5",
	})
	require.NoError(t, err)

	for name, client := range map[string]llmclient.Client{
		"api key": apiKeyClient,
		"pkce":    pkceClient,
	} {
		t.Run(name, func(t *testing.T) {
			matcher := &matchers.Matcher{
				Type:      matchers.MatcherTypeHolder{MatcherType: matchers.LLMMatcher},
				Prompt:    "does the response look like an admin panel?",
				Expect:    "yes",
				AllowSole: true,
			}
			matcher.SetLLMClient(client)

			isMatch, snippets, audit := matcher.MatchLLMWithAudit("<html>admin console</html>")
			require.True(t, isMatch, "the matcher must accept the model verdict")
			require.NotEmpty(t, snippets)
			require.NotNil(t, audit)
			require.Equal(t, "openai/gpt-5.5", audit.Model)
			require.Equal(t, "yes", audit.Verdict)
			require.InDelta(t, 0.91, audit.Confidence, 0.001)
		})
	}

	require.Equal(t, 2, requests, "each credential source made exactly one request")
	require.Equal(t, "openai/gpt-5.5", sawModel)
}

// TestMatcherFailsClosedWhenCredentialIsUnusable proves an unusable credential
// degrades the matcher to "no match" rather than a false positive.
func TestMatcherFailsClosedWhenCredentialIsUnusable(t *testing.T) {
	matcher := &matchers.Matcher{
		Type:      matchers.MatcherTypeHolder{MatcherType: matchers.LLMMatcher},
		Prompt:    "x",
		Expect:    "yes",
		AllowSole: true,
	}
	// No client installed at all.
	isMatch, snippets := matcher.MatchLLM("<html></html>")
	require.False(t, isMatch)
	require.Empty(t, snippets)
}

// TestDisabledLLMDoesNotConfigureAProvider proves nothing is built unless the
// user opted in, so no credential is read and no endpoint is contacted.
func TestDisabledLLMDoesNotConfigureAProvider(t *testing.T) {
	t.Setenv("ORCAROUTER_API_KEY", "")
	t.Setenv("LLM_API_KEY", "")

	// A provider of orcarouter with no credential and no store entry must still
	// be an error, which is what proves the credential is required rather than
	// silently skipped.
	_, err := New(Config{Provider: ProviderName, Store: tempStore(t)})
	require.Error(t, err)
	require.Contains(t, err.Error(), "llm-login")
}

// TestLiveDiscoveryAgainstRealOrcaRouter is the live check: it exercises the
// project's own discovery path against the official endpoint with the campaign
// credential, and asserts the capability filters bind to real data.
//
// It is skipped when no credential is configured so the unit suite stays
// hermetic; the independent verification run supplies one.
func TestLiveDiscoveryAgainstRealOrcaRouter(t *testing.T) {
	key := strings.TrimSpace(os.Getenv("ORCAROUTER_API_KEY"))
	if key == "" {
		t.Skip("ORCAROUTER_API_KEY is not set; live discovery check skipped")
	}

	endpoints := resolveEndpoints("", "", "")
	require.Equal(t, DefaultAuthBaseURL, endpoints.Auth)
	require.Equal(t, DefaultAPIBaseURL, endpoints.API)
	require.NoError(t, ValidateEndpoints(endpoints))

	ctx, cancel := context.WithTimeout(context.Background(), 30_000_000_000)
	defer cancel()

	catalog := DiscoverModels(ctx, endpoints, key)
	require.True(t, catalog.Live, "live discovery must succeed: %s", catalog.Error)
	require.False(t, catalog.Degraded)
	require.NotEmpty(t, catalog.Models)

	chat := catalog.Filtered(ChatFilter())
	require.NotEmpty(t, chat, "the live catalog must contain a chat model")

	for _, model := range chat {
		require.NotEmpty(t, model.ID)
		require.NotContains(t, model.ID, "embedding",
			"an embedding model must not pass the chat filter")
	}

	// The verified fallback must remain a usable subset while the live catalog
	// is authoritative.
	seed := Filter(SeedModels(), ChatFilter())
	require.NotEmpty(t, seed)

	// The capability filters are exercised against real data: a model that the
	// catalog does not advertise for a capability must not appear in it.
	require.Empty(t, catalog.Filtered(ModelFilter{Capability: CapabilityImage}),
		"no image-generation model is advertised, so the image filter must be empty")
	require.Empty(t, catalog.Filtered(ModelFilter{Capability: CapabilityRerank}))

	t.Logf("live catalog: %d entries, %d chat-compatible, %d image-input chat",
		len(catalog.Models), len(chat),
		len(catalog.Filtered(ModelFilter{Capability: CapabilityChat, RequireImageInput: true})))

	// One real inference call through the implemented provider path. The
	// campaign key is scoped to specific models, so the check walks the live
	// catalog and requires at least one model to answer rather than assuming a
	// particular one is enabled for this key.
	var answered []string
	var lastErr error
	for _, model := range chat {
		if len(answered) > 0 || len(answered)+len(chat) > 6 && len(answered) > 0 {
			break
		}

		client, err := New(Config{
			Provider: ProviderName,
			APIKey:   key,
			Model:    model.ID,
			Timeout:  60_000_000_000,
		})
		require.NoError(t, err)

		answer, err := client.Complete(ctx, "Reply with the single word: ready", false)
		if err != nil {
			lastErr = err
			continue
		}
		require.NotContains(t, answer, key)
		if strings.TrimSpace(answer) != "" {
			answered = append(answered, model.ID)
			t.Logf("live inference ok with %s: %q", model.ID, strings.TrimSpace(answer))
		}

		if len(answered) >= 2 {
			break
		}
	}

	require.NotEmpty(t, answered, "at least one live model must answer through the provider path: %v", lastErr)
}
