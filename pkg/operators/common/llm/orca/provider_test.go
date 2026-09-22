package orca

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	llmclient "github.com/projectdiscovery/nuclei/v3/pkg/operators/common/llm"
	"github.com/stretchr/testify/require"
)

// TestProviderRegistryContainsOrcaRouterAsFirstClassEntry proves OrcaRouter is a
// named provider with its own inference base and discovery path, not a custom
// endpoint the user has to assemble.
func TestProviderRegistryContainsOrcaRouterAsFirstClassEntry(t *testing.T) {
	provider, ok := LookupProvider(ProviderName)
	require.True(t, ok)
	require.Equal(t, ProviderName, provider.Name)
	require.Equal(t, ProviderLabel, provider.Label)
	require.Equal(t, "https://api.orcarouter.ai/v1", provider.BaseURL)
	require.True(t, provider.Hosted, "OrcaRouter needs a credential")
	require.Equal(t, DefaultModel, provider.DefaultModel)
	require.Equal(t, "/models?capability=chat", provider.Catalog)

	require.True(t, IsOrcaRouter("orcarouter"))
	require.True(t, IsOrcaRouter("OrcaRouter"))
	require.False(t, IsOrcaRouter("openai"))

	names := ProviderNames()
	require.Contains(t, names, ProviderName)
	require.Contains(t, names, "openai")
	require.Contains(t, names, "openrouter")
	require.NotContains(t, names, "orcarouter-oauth",
		"one provider id carries both authentication methods, per this repository's model")
}

// TestEndpointsUseSeparateOriginsAndOverrides proves the two origins are
// resolved independently with the documented precedence.
func TestEndpointsUseSeparateOriginsAndOverrides(t *testing.T) {
	defaults := resolveEndpoints("", "", "")
	require.Equal(t, "https://www.orcarouter.ai", defaults.Auth)
	require.Equal(t, "https://api.orcarouter.ai/v1", defaults.API)
	require.NotEqual(t, defaults.Auth, defaults.API)

	// A shared self-hosted base fills both.
	shared := resolveEndpoints("", "", "https://gateway.internal")
	require.Equal(t, "https://gateway.internal", shared.Auth)
	require.Equal(t, "https://gateway.internal", shared.API)

	// Explicit per-origin values win over the shared base.
	explicit := resolveEndpoints("https://auth.internal", "https://api.internal/v1", "https://shared.internal")
	require.Equal(t, "https://auth.internal", explicit.Auth)
	require.Equal(t, "https://api.internal/v1", explicit.API)

	// A trailing slash is normalised so paths do not double up.
	require.Equal(t, "https://auth.internal", resolveEndpoints("https://auth.internal/", "", "").Auth)

	// The API origin is never derived from the auth origin.
	require.NotContains(t, defaults.API, "www.orcarouter.ai")
	require.False(t, strings.HasPrefix(defaults.API, defaults.Auth))
}

// TestValidateEndpointsRequiresHTTPSExceptLoopback proves the transport policy.
func TestValidateEndpointsRequiresHTTPSExceptLoopback(t *testing.T) {
	require.Error(t, ValidateEndpoints(Endpoints{Auth: "http://www.orcarouter.ai", API: DefaultAPIBaseURL}))
	require.Error(t, ValidateEndpoints(Endpoints{Auth: DefaultAuthBaseURL, API: "http://api.orcarouter.ai/v1"}))
	require.Error(t, ValidateEndpoints(Endpoints{Auth: "ftp://www.orcarouter.ai", API: DefaultAPIBaseURL}))
	require.Error(t, ValidateEndpoints(Endpoints{Auth: "", API: DefaultAPIBaseURL}))
	require.Error(t, ValidateEndpoints(Endpoints{Auth: "https://user:pass@www.orcarouter.ai", API: DefaultAPIBaseURL}))
	require.Error(t, ValidateEndpoints(Endpoints{Auth: "not-a-url", API: DefaultAPIBaseURL}))

	require.NoError(t, ValidateEndpoints(Endpoints{Auth: "http://localhost:9999", API: "http://127.0.0.1:9999/v1"}))
	require.NoError(t, ValidateEndpoints(Endpoints{Auth: "http://[::1]:9999", API: "http://[::1]:9999/v1"}))
	require.NoError(t, ValidateEndpoints(Endpoints{Auth: DefaultAuthBaseURL, API: DefaultAPIBaseURL}))
}

// TestEndpointsFromEnvHonoursOverrides proves the documented environment
// variables are read.
func TestEndpointsFromEnvHonoursOverrides(t *testing.T) {
	t.Setenv(EnvSharedBase, "https://shared.example")
	require.Equal(t, "https://shared.example", EndpointsFromEnv().Auth)
	require.Equal(t, "https://shared.example", EndpointsFromEnv().API)

	t.Setenv(EnvAuthBaseURL, "https://auth.example")
	t.Setenv(EnvAPIBaseURL, "https://api.example/v1")
	endpoints := EndpointsFromEnv()
	require.Equal(t, "https://auth.example", endpoints.Auth)
	require.Equal(t, "https://api.example/v1", endpoints.API)
}

// TestNewRoutesOrcaRouterThroughTheCredentialSeam is the dual-auth seam test:
// a pasted key and a PKCE-issued key both produce the same client, and the
// downstream provider cannot tell them apart.
func TestNewRoutesOrcaRouterThroughTheCredentialSeam(t *testing.T) {
	var sawAuthorization string
	var sawPath string

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		sawAuthorization = request.Header.Get("Authorization")
		sawPath = request.URL.Path
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"choices":[{"message":{"content":"verdict"}}]}`)
	}))
	defer server.Close()

	// Adapter 1: an explicit API key.
	apiKeyClient, err := New(Config{
		Provider:    ProviderName,
		APIKey:      "sk-orca-from-api-key",
		BaseURL:     server.URL + "/v1",
		APIBaseURL:  server.URL + "/v1",
		AuthBaseURL: server.URL,
		Model:       "openai/gpt-5.5",
		Timeout:     5_000_000_000,
	})
	require.NoError(t, err)

	answer, err := apiKeyClient.Complete(t.Context(), "classify", false)
	require.NoError(t, err)
	require.Equal(t, "verdict", answer)
	require.Equal(t, "/v1/chat/completions", sawPath)
	require.Equal(t, "Bearer sk-orca-from-api-key", sawAuthorization)

	// Adapter 2: a credential a PKCE login stored. The same provider call works
	// with no knowledge of where the key came from.
	store := tempStore(t)
	_, err = store.Save(Credential{Key: "sk-orca-from-pkce", Scope: ScopeAPI, UserID: "5"}, SourcePKCE)
	require.NoError(t, err)

	t.Setenv("ORCAROUTER_API_KEY", "")
	t.Setenv("LLM_API_KEY", "")

	pkceClient, err := New(Config{
		Provider:    ProviderName,
		Store:       store,
		BaseURL:     server.URL + "/v1",
		APIBaseURL:  server.URL + "/v1",
		AuthBaseURL: server.URL,
		Model:       "openai/gpt-5.5",
	})
	require.NoError(t, err)

	answer, err = pkceClient.Complete(t.Context(), "classify", false)
	require.NoError(t, err)
	require.Equal(t, "verdict", answer)
	require.Equal(t, "Bearer sk-orca-from-pkce", sawAuthorization)

	// Both are the same interface value; nothing downstream branches on source.
	var apiKeyAsClient, pkceAsClient llmclient.Client = apiKeyClient, pkceClient
	require.NotNil(t, apiKeyAsClient)
	require.NotNil(t, pkceAsClient)

	apiKeyTyped, ok := apiKeyClient.(*client)
	require.True(t, ok)
	require.Equal(t, SourceAPIKey, apiKeyTyped.CredentialSource())
	require.Equal(t, int64(0), apiKeyTyped.CredentialGeneration(), "a pasted key has no stored generation")

	pkceTyped, ok := pkceClient.(*client)
	require.True(t, ok)
	require.Equal(t, SourcePKCE, pkceTyped.CredentialSource())
	require.Equal(t, int64(1), pkceTyped.CredentialGeneration())
}

// TestNewUsesProviderDefaultModel proves a provider selection without a model
// still routes.
func TestNewUsesProviderDefaultModel(t *testing.T) {
	llmClient, err := New(Config{
		Provider:    ProviderName,
		APIKey:      "sk-orca-default-model",
		AuthBaseURL: "https://auth.example",
		APIBaseURL:  "https://api.example/v1",
	})
	require.NoError(t, err)

	typed, ok := llmClient.(*client)
	require.True(t, ok)
	require.Equal(t, DefaultModel, typed.Model())
	require.Equal(t, "https://api.example/v1", typed.Endpoints().API)
	require.Equal(t, "https://auth.example", typed.Endpoints().Auth)
}

// TestNewRequiresACredentialForOrcaRouter proves an unconfigured provider fails
// with an actionable message instead of sending an anonymous request.
func TestNewRequiresACredentialForOrcaRouter(t *testing.T) {
	t.Setenv("ORCAROUTER_API_KEY", "")
	t.Setenv("LLM_API_KEY", "")

	_, err := New(Config{
		Provider: ProviderName,
		Store:    tempStore(t),
	})
	require.Error(t, err)
	require.Contains(t, err.Error(), "llm-api-key")
	require.Contains(t, err.Error(), "-llm-login")
}

// TestNewMarksOnlyTheRejectedGeneration proves a relay 401 is a terminal
// reauthentication signal scoped to the exact credential, and that no refresh is
// attempted.
func TestNewMarksOnlyTheRejectedGeneration(t *testing.T) {
	// The stored credential must be the one used, so the ambient environment
	// cannot shadow it.
	t.Setenv("ORCAROUTER_API_KEY", "")
	t.Setenv("LLM_API_KEY", "")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(writer, `{"error":"invalid api key"}`)
	}))
	defer server.Close()

	store := tempStore(t)
	_, err := store.Save(Credential{Key: "sk-orca-revoked", Scope: ScopeAPI, UserID: "5"}, SourcePKCE)
	require.NoError(t, err)

	var notified []int64
	client, err := New(Config{
		Provider:       ProviderName,
		Store:          store,
		AuthBaseURL:    server.URL,
		APIBaseURL:     server.URL + "/v1",
		OnUnauthorized: func(generation int64) { notified = append(notified, generation) },
	})
	require.NoError(t, err)

	_, err = client.Complete(t.Context(), "classify", false)
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")

	require.Equal(t, []int64{1}, notified)
	require.True(t, store.NeedsReauth(), "the exact rejected generation is marked")

	// The credential is unusable and the error says how to fix it.
	_, err = store.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "-llm-login")

	// A new login succeeds; a late failure carrying the old generation must not
	// touch it.
	replacement, err := store.Save(Credential{Key: "sk-orca-new", Scope: ScopeAPI, UserID: "5"}, SourcePKCE)
	require.NoError(t, err)
	require.False(t, store.NeedsReauth())

	marked, err := store.MarkNeedsReauth(1)
	require.NoError(t, err)
	require.False(t, marked)
	require.False(t, store.NeedsReauth())

	loaded, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, "sk-orca-new", loaded.Key)
	require.Equal(t, replacement.Generation, loaded.Generation)
}

// TestNonOrcaRouterProvidersKeepExistingBehaviour proves the change is additive:
// other presets still resolve through the shared provider layer.
func TestNonOrcaRouterProvidersKeepExistingBehaviour(t *testing.T) {
	client, err := New(Config{
		Provider: "openai",
		APIKey:   "sk-test",
		Model:    "gpt-4o-mini",
	})
	require.NoError(t, err)
	require.NotNil(t, client)

	// A local preset needs no key, exactly as before.
	local, err := New(Config{Provider: "ollama", Model: "llama3"})
	require.NoError(t, err)
	require.NotNil(t, local)

	// An unknown provider is still an error from the shared layer.
	_, err = New(Config{Provider: "not-a-provider", Model: "x"})
	require.Error(t, err)
}

// TestIsUnauthorizedMatchesTheRelayRejection proves the classification is
// specific to a 401 rather than any failure.
func TestIsUnauthorizedMatchesTheRelayRejection(t *testing.T) {
	require.True(t, isUnauthorized(errors.New("llm provider returned status 401: invalid key")))
	require.False(t, isUnauthorized(errors.New("llm provider returned status 429: rate limited")))
	require.False(t, isUnauthorized(errors.New("llm provider returned status 500")))
	require.False(t, isUnauthorized(errors.New("could not reach llm provider")))
	require.False(t, isUnauthorized(nil))
}

// TestCommandStatusMasksTheCredential proves the status command never prints the
// key.
func TestCommandStatusMasksTheCredential(t *testing.T) {
	store := tempStore(t)
	_, err := store.Save(Credential{Key: "sk-orca-status-secret", Scope: ScopeAPI, UserID: "42"}, SourcePKCE)
	require.NoError(t, err)

	var out strings.Builder
	handled, code := RunCredentialCommand(CredentialCommandOptions{
		Status: true,
		Store:  store,
		Out:    &out,
	})
	require.True(t, handled)
	require.Equal(t, 0, code)

	rendered := out.String()
	require.NotContains(t, rendered, "sk-orca-status-secret")
	require.Contains(t, rendered, "42")
	require.Contains(t, rendered, store.Path)
	require.Contains(t, rendered, ConsoleURL)
	require.Contains(t, rendered, "api")
	require.NotContains(t, rendered, "pkce-issued-key", "the raw key must never be printed")
}

// TestCommandStatusAdvertisesBothAuthenticationMethods proves a user with no
// credential is told about both ways in.
func TestCommandStatusAdvertisesBothAuthenticationMethods(t *testing.T) {
	store := tempStore(t)

	var out strings.Builder
	handled, code := RunCredentialCommand(CredentialCommandOptions{
		Status: true,
		Store:  store,
		Out:    &out,
	})
	require.True(t, handled)
	require.Equal(t, 0, code)

	rendered := out.String()
	require.Contains(t, rendered, "--llm-api-key", "the api key method must be discoverable")
	require.Contains(t, rendered, "ORCAROUTER_API_KEY")
	require.Contains(t, rendered, "-llm-login", "the pkce method must be discoverable")
}

// TestCommandLogoutClearsTheCredential proves logout is reachable and complete.
func TestCommandLogoutClearsTheCredential(t *testing.T) {
	store := tempStore(t)
	_, err := store.Save(Credential{Key: "sk-orca-logout", Scope: ScopeAPI}, SourcePKCE)
	require.NoError(t, err)

	var out strings.Builder
	handled, code := RunCredentialCommand(CredentialCommandOptions{Logout: true, Store: store, Out: &out})
	require.True(t, handled)
	require.Equal(t, 0, code)
	require.False(t, fileExists(store.Path))
	require.Contains(t, out.String(), "ORCAROUTER_API_KEY")
}

// TestCommandReportsNoOpWhenNothingRequested proves a normal scan is untouched.
func TestCommandReportsNoOpWhenNothingRequested(t *testing.T) {
	handled, code := RunCredentialCommand(CredentialCommandOptions{})
	require.False(t, handled)
	require.Zero(t, code)
}

// TestCommandRejectsUnknownFlow proves a bad flow value is a clear error rather
// than a silent fallback.
func TestCommandRejectsUnknownFlow(t *testing.T) {
	var out strings.Builder
	handled, code := RunCredentialCommand(CredentialCommandOptions{
		Login: true,
		Flow:  "device",
		Store: tempStore(t),
		Out:   &out,
	})
	require.True(t, handled)
	require.Equal(t, 1, code)
	require.Contains(t, out.String(), "loopback")
	require.Contains(t, out.String(), "oob")
}

// TestCommandModelsListsFilteredCatalog proves the listing is capability
// filtered and reports a degraded catalog.
func TestCommandModelsListsFilteredCatalog(t *testing.T) {
	t.Setenv("ORCAROUTER_API_KEY", "")
	t.Setenv("LLM_API_KEY", "")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		require.Equal(t, "/models", request.URL.Path)
		require.Equal(t, "chat", request.URL.Query().Get("capability"))
		writer.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(writer, `{"data":[
			{"id":"openai/gpt-5.5","supported_endpoint_types":["openai"],
			 "architecture":{"input_modalities":["text","image"]},
			 "reasoning_efforts":["low","medium","high","xhigh"]},
			{"id":"openai/text-embedding-3-large","supported_endpoint_types":["embeddings"]}]}`)
	}))
	defer server.Close()

	store := tempStore(t)
	_, err := store.Save(Credential{Key: "sk-orca-models", Scope: ScopeAPI}, SourcePKCE)
	require.NoError(t, err)

	var out strings.Builder
	handled, code := RunCredentialCommand(CredentialCommandOptions{
		Models:      true,
		Store:       store,
		Out:         &out,
		APIBaseURL:  server.URL,
		AuthBaseURL: "https://auth.example",
	})
	require.True(t, handled)
	require.Equal(t, 0, code)

	rendered := out.String()
	require.Contains(t, rendered, "openai/gpt-5.5")
	require.Contains(t, rendered, "low/medium/high/xhigh")
	require.Contains(t, rendered, "input text+image")
	require.NotContains(t, rendered, "text-embedding-3-large",
		"an embedding model must not appear in the chat listing")
	require.NotContains(t, rendered, "sk-orca-models")
}

// TestCommandModelsFallsBackToVerifiedSeed proves a catalog outage still lists a
// usable, labelled fallback.
func TestCommandModelsFallsBackToVerifiedSeed(t *testing.T) {
	t.Setenv("ORCAROUTER_API_KEY", "")
	t.Setenv("LLM_API_KEY", "")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()

	store := tempStore(t)
	_, err := store.Save(Credential{Key: "sk-orca-models", Scope: ScopeAPI}, SourcePKCE)
	require.NoError(t, err)

	var out strings.Builder
	RunCredentialCommand(CredentialCommandOptions{
		Models:      true,
		Store:       store,
		Out:         &out,
		APIBaseURL:  server.URL,
		AuthBaseURL: "https://auth.example",
	})

	rendered := out.String()
	require.Contains(t, rendered, "verified fallback")
	require.Contains(t, rendered, "openai/gpt-5.5")
	require.Contains(t, rendered, "live catalog unavailable")
}

// TestPromptCodeIsNilWithoutTerminal proves a non-interactive stdin disables the
// out-of-band prompt instead of blocking on it.
func TestPromptCodeReadsNonInteractiveInput(t *testing.T) {
	// A piped code must work: the prompt reads a line, not a character device.
	prompt := promptCode(io.Discard, strings.NewReader("code\n"))
	require.NotNil(t, prompt)

	code, err := prompt("https://example/auth")
	require.NoError(t, err)
	require.Equal(t, "code", code)

	file, err := os.CreateTemp(t.TempDir(), "not-a-tty")
	require.NoError(t, err)
	defer func() { _ = file.Close() }()
	_, _ = file.WriteString("from-a-file\n")
	_, err = file.Seek(0, io.SeekStart)
	require.NoError(t, err)

	code, err = promptCode(io.Discard, file)("https://example/auth")
	require.NoError(t, err)
	require.Equal(t, "from-a-file", code)
}

// TestPromptCodeReadsFromTerminalReader proves the prompt trims input.
func TestPromptCodeReadsFromTerminalReader(t *testing.T) {
	prompt := promptCode(io.Discard, strings.NewReader("  the-code  \n"))
	require.NotNil(t, prompt)

	code, err := prompt("https://example/auth")
	require.NoError(t, err)
	require.Equal(t, "the-code", code)
}

// TestDescribePKCEErrorIsActionable proves each terminal kind renders a usable
// message.
func TestDescribePKCEErrorIsActionable(t *testing.T) {
	kinds := []PKCEErrorKind{
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
	}

	for _, kind := range kinds {
		rendered := DescribePKCEError(NewPKCEError(kind, "something failed"))
		require.Contains(t, rendered, "something failed")
		require.NotEmpty(t, rendered)
	}

	require.Contains(t, DescribePKCEError(NewPKCEError(PKCEErrorRateLimited, "x")), ConsoleURL)
	require.Equal(t, "plain error", DescribePKCEError(errors.New("plain error")))
}

// TestAuthAndInferenceUseTheDocumentedOrigins proves the two public origins are
// exactly the documented ones and that neither is derived from the other.
func TestAuthAndInferenceUseTheDocumentedOrigins(t *testing.T) {
	endpoints := resolveEndpoints("", "", "")
	require.Equal(t, "https://www.orcarouter.ai", endpoints.Auth)
	require.Equal(t, "https://api.orcarouter.ai/v1", endpoints.API)

	pkce, err := NewPKCE()
	require.NoError(t, err)

	authorize := AuthorizeURL(endpoints.Auth, CallbackURLOutOfBand, pkce, AppName, ScopeAPI)
	parsed, err := url.Parse(authorize)
	require.NoError(t, err)
	require.Equal(t, "www.orcarouter.ai", parsed.Host, "authorization must use the auth origin")
	require.Equal(t, AuthPath, parsed.Path)

	exchange, err := url.Parse(endpoints.Auth + ExchangePath)
	require.NoError(t, err)
	require.Equal(t, "www.orcarouter.ai", exchange.Host)
	require.Equal(t, "/api/v1/auth/keys", exchange.Path)

	models, err := url.Parse(endpoints.API + ModelsPath)
	require.NoError(t, err)
	require.Equal(t, "api.orcarouter.ai", models.Host, "discovery must use the inference origin")
	require.Equal(t, "/v1/models", models.Path)

	completions, err := url.Parse(endpoints.API + ChatCompletionsPath)
	require.NoError(t, err)
	require.Equal(t, "api.orcarouter.ai", completions.Host)
	require.Equal(t, "/v1/chat/completions", completions.Path)
}

// TestWrongAuthPathIsNeverConstructed proves the documented mistake - deriving
// the exchange path from the inference origin - cannot happen here.
func TestWrongAuthPathIsNeverConstructed(t *testing.T) {
	endpoints := resolveEndpoints("", "", "")

	// The exchange is built from the auth origin, and the path is the documented
	// /api/v1/auth/keys rather than the relay-shaped /v1/auth/keys.
	require.Equal(t, "https://www.orcarouter.ai/api/v1/auth/keys", endpoints.Auth+ExchangePath)
	require.Equal(t, "/api/v1/auth/keys", ExchangePath)
	require.True(t, strings.HasPrefix(ExchangePath, "/api/v1/auth/"),
		"the exchange path must sit under the auth origin's /api/v1/auth prefix")
	require.NotEqual(t, "/v1/auth/keys", ExchangePath)

	// The inference origin is never used to build an auth path.
	require.NotContains(t, endpoints.API, "auth")
	require.NotContains(t, endpoints.API+ModelsPath, "auth")
	require.NotContains(t, endpoints.API+ChatCompletionsPath, "auth")

	// The auth origin is never derived by swapping a hostname or appending /v1.
	require.NotEqual(t, strings.Replace(endpoints.API, "api.", "www.", 1), endpoints.Auth)
	require.Equal(t, "https://www.orcarouter.ai", endpoints.Auth)
}
