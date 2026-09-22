package orca

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func tempStore(t *testing.T) *CredentialStore {
	t.Helper()

	return &CredentialStore{Path: filepath.Join(t.TempDir(), "orcarouter.json")}
}

// TestAPIKeySourceValidatesShape proves the pasted-key path accepts the
// documented prefix and rejects obvious mistakes with an actionable message.
func TestAPIKeySourceValidatesShape(t *testing.T) {
	valid := APIKeySource{Key: "  sk-orca-abc123  "}
	credential, err := valid.Credential()
	require.NoError(t, err)
	require.Equal(t, "sk-orca-abc123", credential.Key, "surrounding whitespace is ignored")
	require.Equal(t, SourceAPIKey, valid.Source())

	_, err = APIKeySource{Key: ""}.Credential()
	require.ErrorIs(t, err, ErrNoCredential)

	_, err = APIKeySource{Key: "not-a-key"}.Credential()
	require.Error(t, err)
	require.Contains(t, err.Error(), APIKeyPrefix)
	require.Contains(t, err.Error(), ConsoleURL, "the error must say where to create a key")

	_, err = APIKeySource{Key: "sk-orca-has space"}.Credential()
	require.Error(t, err)
}

// TestCredentialMasking proves a credential can be shown without being revealed.
func TestCredentialMasking(t *testing.T) {
	credential := Credential{Key: "sk-orca-abcdefghijklmnop"}
	masked := credential.Masked()

	require.NotEqual(t, credential.Key, masked)
	require.Contains(t, masked, "sk-orca-")
	require.NotContains(t, masked, "ijklmnop", "the middle of the key must not be shown")
	require.Len(t, masked, len("sk-orca-")+4+4)

	require.Empty(t, Credential{}.Masked())
	require.Equal(t, "***", Credential{Key: "abc"}.Masked())
}

// TestStoreSaveLoadClear proves the store round-trips a credential, keeps it
// owner-only, and clears it.
func TestStoreSaveLoadClear(t *testing.T) {
	store := tempStore(t)

	_, err := store.Load()
	require.ErrorIs(t, err, ErrNoCredential)

	saved, err := store.Save(Credential{Key: "sk-orca-key-one", Scope: ScopeAPI, UserID: "1"}, SourcePKCE)
	require.NoError(t, err)
	require.Equal(t, int64(1), saved.Generation)

	loaded, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, "sk-orca-key-one", loaded.Key)
	require.Equal(t, "1", loaded.UserID)
	require.Equal(t, int64(1), loaded.Generation)

	info, err := os.Stat(store.Path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(credentialFileMode), info.Mode().Perm(),
		"the credential file must be owner-only")

	// A second save increments the generation, which is what makes the 401
	// transition safe.
	second, err := store.Save(Credential{Key: "sk-orca-key-two", Scope: ScopeAPI, UserID: "2"}, SourceAPIKey)
	require.NoError(t, err)
	require.Equal(t, int64(2), second.Generation)

	require.NoError(t, store.Clear())
	_, err = store.Load()
	require.ErrorIs(t, err, ErrNoCredential)

	require.NoError(t, store.Clear(), "clearing twice is not an error")
}

// TestStoreRejectsEmptyCredential proves an empty key is never persisted.
func TestStoreRejectsEmptyCredential(t *testing.T) {
	store := tempStore(t)

	_, err := store.Save(Credential{Key: "   "}, SourceAPIKey)
	require.Error(t, err)
	require.False(t, fileExists(store.Path))
}

// TestStoreNeedsReauthIsGenerationSafe is the core lifecycle property: a late
// failure from a superseded credential must not poison a newer one.
func TestStoreNeedsReauthIsGenerationSafe(t *testing.T) {
	store := tempStore(t)

	first, err := store.Save(Credential{Key: "sk-orca-first", Scope: ScopeAPI}, SourcePKCE)
	require.NoError(t, err)

	// The rejected generation matches: mark it.
	marked, err := store.MarkNeedsReauth(first.Generation)
	require.NoError(t, err)
	require.True(t, marked)
	require.True(t, store.NeedsReauth())

	// A marked credential is unusable but is not deleted: a misclassified
	// failure must not destroy the only copy of a working key.
	_, err = store.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "revoked")
	require.True(t, fileExists(store.Path))

	// A new login replaces it and clears the marker.
	second, err := store.Save(Credential{Key: "sk-orca-second", Scope: ScopeAPI}, SourcePKCE)
	require.NoError(t, err)
	require.False(t, store.NeedsReauth())

	// A late failure carrying the OLD generation must be ignored.
	marked, err = store.MarkNeedsReauth(first.Generation)
	require.NoError(t, err)
	require.False(t, marked, "a stale generation must not mark the new credential")
	require.False(t, store.NeedsReauth())

	loaded, err := store.Load()
	require.NoError(t, err)
	require.Equal(t, "sk-orca-second", loaded.Key)
	require.Equal(t, second.Generation, loaded.Generation)
}

// TestStoreCorruptFileIsTerminal proves a damaged credential file produces a
// clear terminal error rather than a panic or a silent empty key.
func TestStoreCorruptFileIsTerminal(t *testing.T) {
	store := tempStore(t)
	require.NoError(t, os.MkdirAll(filepath.Dir(store.Path), 0o700))
	require.NoError(t, os.WriteFile(store.Path, []byte("{not json"), 0o600))

	_, err := store.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "json")

	require.NoError(t, os.WriteFile(store.Path, []byte(`{"key":""}`), 0o600))
	_, err = store.Load()
	require.Error(t, err)
	require.Contains(t, err.Error(), "no key")
}

// TestNoRefreshGrantExists proves the package never models a refresh token: a
// PKCE-issued key is durable, and the stored shape has no refresh field.
func TestNoRefreshGrantExists(t *testing.T) {
	store := tempStore(t)
	_, err := store.Save(Credential{Key: "sk-orca-durable", Scope: ScopeAPI}, SourcePKCE)
	require.NoError(t, err)

	raw, err := os.ReadFile(store.Path)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "refresh")
	require.Contains(t, string(raw), `"source":"pkce"`)
}

// TestRedactRemovesSecrets proves the redaction helper covers the values that
// must not reach a log.
func TestRedactRemovesSecrets(t *testing.T) {
	verifier := "verifier-value"
	key := "sk-orca-secret"
	message := "failed with key=" + key + " verifier=" + verifier

	redacted := Redact(message, key, verifier)
	require.NotContains(t, redacted, key)
	require.NotContains(t, redacted, verifier)
	require.Contains(t, redacted, "[REDACTED]")

	require.Equal(t, "unchanged", Redact("unchanged", "", "  "))
}

// TestWrapSecretErrorStripsSecrets proves an error built from a transport error
// cannot carry a secret.
func TestWrapSecretErrorStripsSecrets(t *testing.T) {
	err := wrapSecretError(errors.New("dial failed for sk-orca-leak"), "login failed", "sk-orca-leak")
	require.Error(t, err)
	require.NotContains(t, err.Error(), "sk-orca-leak")
	require.Nil(t, wrapSecretError(nil, "ignored"))
}

func fileExists(path string) bool {
	_, err := os.Stat(path)

	return err == nil
}

// TestDefaultCredentialSourcePrefersExplicitKey proves an explicit key wins over
// the stored one, so a user can point a single scan at another account.
func TestDefaultCredentialSourcePrefersExplicitKey(t *testing.T) {
	store := tempStore(t)
	_, err := store.Save(Credential{Key: "sk-orca-stored", Scope: ScopeAPI}, SourcePKCE)
	require.NoError(t, err)

	explicit := DefaultCredentialSource("sk-orca-explicit", store)
	require.Equal(t, SourceAPIKey, explicit.Source())
	credential, err := explicit.Credential()
	require.NoError(t, err)
	require.Equal(t, "sk-orca-explicit", credential.Key)

	stored := DefaultCredentialSource("   ", store)
	credential, err = stored.Credential()
	require.NoError(t, err)
	require.Equal(t, "sk-orca-stored", credential.Key)
}

// TestAPIKeyFromEnvPrecedence proves the provider-specific variable wins over
// the shared one.
func TestAPIKeyFromEnvPrecedence(t *testing.T) {
	t.Setenv("ORCAROUTER_API_KEY", "")
	t.Setenv("LLM_API_KEY", "sk-orca-shared")
	require.Equal(t, "sk-orca-shared", APIKeyFromEnv())

	t.Setenv("ORCAROUTER_API_KEY", "sk-orca-specific")
	require.Equal(t, "sk-orca-specific", APIKeyFromEnv())

	require.True(t, strings.HasPrefix(APIKeyFromEnv(), APIKeyPrefix))
}
