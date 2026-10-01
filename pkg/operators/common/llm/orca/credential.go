package orca

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/utils/errkit"
)

// Credential is what both authentication methods produce: an ordinary
// OrcaRouter API key. Nothing downstream of this type can tell whether the key
// was pasted by the user or issued by the PKCE connect flow, which is the point
// of the seam - the provider, the model catalog and every llm entry point take
// a Credential and never a source.
type Credential struct {
	// Key is the sk-orca-... API key. It is never logged.
	Key string
	// Scope is the scope the server actually granted, not the one requested.
	Scope string
	// UserID identifies the OrcaRouter account the key belongs to, when known.
	UserID string
	// Source records which authentication method produced the key.
	Source Source
	// Generation increments on every stored credential. It is what makes the
	// terminal 401 transition safe: a late failure carries the generation it
	// was issued for and is ignored once the stored generation has moved on.
	Generation int64
	// IssuedAt records when this credential was stored.
	IssuedAt time.Time
}

// Masked returns the credential in a form safe for logs and UI. It keeps only a
// short prefix and suffix so a user can recognise which key is in use.
func (c Credential) Masked() string {
	key := strings.TrimSpace(c.Key)
	if key == "" {
		return ""
	}
	if len(key) <= 11 {
		return strings.Repeat("*", len(key))
	}

	return key[:8] + strings.Repeat("*", 4) + key[len(key)-4:]
}

// Source names the authentication method that produced a credential.
type Source string

const (
	// SourceAPIKey is a key the user pasted from the OrcaRouter console.
	SourceAPIKey Source = "api_key"
	// SourcePKCE is a key issued by the OAuth 2.0 + PKCE connect flow.
	SourcePKCE Source = "pkce"
)

// CredentialSource is the seam the two authentication methods implement. An
// adapter's only job is to obtain or read a key; provider wiring, model
// discovery and the llm entry points never call an adapter directly.
type CredentialSource interface {
	// Credential returns the key to use, or an error explaining what the user
	// has to do about it.
	Credential() (Credential, error)
	// Source names the method, for diagnostics.
	Source() Source
}

// APIKeySource adapts a user-supplied key. The key may come from a flag or from
// the environment; both land here so there is one place that decides what an
// acceptable key looks like.
type APIKeySource struct {
	// Key is the raw value. Surrounding whitespace is ignored.
	Key string
}

// Credential validates the pasted key. Validation is a shape check only: an
// sk-orca- prefix is not proof that a key is valid, and OrcaRouter exposes no
// free, non-billing validation request, so validity is established by the first
// real request rather than by a paid probe.
func (s APIKeySource) Credential() (Credential, error) {
	key := strings.TrimSpace(s.Key)
	if key == "" {
		return Credential{}, ErrNoCredential
	}
	if !strings.HasPrefix(key, APIKeyPrefix) {
		return Credential{}, errkit.Newf(
			"orcarouter api key must start with %q; create one at %s",
			APIKeyPrefix,
			ConsoleURL,
		)
	}
	if strings.ContainsAny(key, " \t\r\n") {
		return Credential{}, errors.New("orcarouter api key contains whitespace")
	}

	return Credential{Key: key, Scope: ScopeAPI, Source: SourceAPIKey}, nil
}

// Source implements CredentialSource.
func (s APIKeySource) Source() Source { return SourceAPIKey }

// StoredCredentialSource adapts the on-disk credential written by either
// method. It is what a scan uses by default: a key that was pasted once or
// issued by a login is reused until OrcaRouter revokes it.
type StoredCredentialSource struct {
	Store *CredentialStore
}

// Credential implements CredentialSource.
func (s StoredCredentialSource) Credential() (Credential, error) {
	if s.Store == nil {
		return Credential{}, ErrNoCredential
	}

	return s.Store.Load()
}

// Source implements CredentialSource.
func (s StoredCredentialSource) Source() Source { return SourceAPIKey }

const (
	// APIKeyPrefix is the documented OrcaRouter key prefix.
	APIKeyPrefix = "sk-orca-"

	// ScopeAPI is the scope the connect flow requests and the one a key used
	// for inference must carry.
	ScopeAPI = "api"

	// credentialFileName is the stored credential inside the nuclei config
	// directory's keys directory. It reuses nuclei's existing secret location
	// (mode 0600) rather than introducing a new secret store.
	credentialFileName = "orcarouter.json"

	credentialFileMode = 0o600
)

// ErrNoCredential means no key is available yet and the user has to supply one.
var ErrNoCredential = errors.New(
	"no orcarouter credential: set --llm-api-key, ORCAROUTER_API_KEY or LLM_API_KEY, or run 'nuclei -llm-login'",
)

// storedCredential is the on-disk representation. It deliberately carries no
// refresh token: a PKCE-issued key is durable but is not an OAuth access token,
// and there is no refresh grant to call.
type storedCredential struct {
	Key                   string    `json:"key"`
	Scope                 string    `json:"scope,omitempty"`
	UserID                string    `json:"user_id,omitempty"`
	Source                Source    `json:"source,omitempty"`
	Generation            int64     `json:"generation"`
	IssuedAt              time.Time `json:"issued_at"`
	NeedsReauth           bool      `json:"needs_reauth,omitempty"`
	NeedsReauthGeneration int64     `json:"needs_reauth_generation,omitempty"`
}

// CredentialStore persists one credential for this application. Reads and
// writes are serialized so two concurrent logins cannot interleave a
// read-modify-write.
type CredentialStore struct {
	// Path overrides the default location. Empty uses nuclei's existing
	// configuration directory.
	Path string

	mu sync.Mutex
}

// DefaultCredentialPath is the store location: nuclei's own configuration
// directory, under the keys directory it already uses for secrets.
func DefaultCredentialPath() string {
	return filepath.Join(config.DefaultConfig.GetKeysDir(), credentialFileName)
}

func (s *CredentialStore) path() string {
	if strings.TrimSpace(s.Path) != "" {
		return s.Path
	}

	return DefaultCredentialPath()
}

// Load returns the stored credential, or ErrNoCredential when there is none.
//
// A credential marked for reauthentication is reported as unusable, but its key
// is not deleted: a transient or misclassified failure must not destroy the
// only copy of a working key before a replacement exists.
func (s *CredentialStore) Load() (Credential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.loadLocked()
}

func (s *CredentialStore) loadLocked() (Credential, error) {
	raw, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return Credential{}, ErrNoCredential
	}
	if err != nil {
		return Credential{}, errkit.Wrap(err, "could not read the stored orcarouter credential")
	}

	var stored storedCredential
	if err := json.Unmarshal(raw, &stored); err != nil {
		return Credential{}, errkit.Wrap(err, "stored orcarouter credential is not valid json")
	}
	if strings.TrimSpace(stored.Key) == "" {
		return Credential{}, errkit.New("stored orcarouter credential has no key")
	}
	if stored.NeedsReauth {
		return Credential{}, errkit.Newf(
			"the orcarouter credential for this account was revoked; run 'nuclei -llm-login' again or paste a new key (%s)",
			ConsoleURL,
		)
	}

	source := stored.Source
	if source == "" {
		source = SourceAPIKey
	}

	return Credential{
		Key:        stored.Key,
		Scope:      stored.Scope,
		UserID:     stored.UserID,
		Source:     source,
		Generation: stored.Generation,
		IssuedAt:   stored.IssuedAt,
	}, nil
}

// Save replaces the stored credential with a new generation. It is called after
// a successful login or after a user pastes a key, and never during a failure
// path, so the previous key survives until a replacement is in hand.
func (s *CredentialStore) Save(credential Credential, source Source) (Credential, error) {
	if strings.TrimSpace(credential.Key) == "" {
		return Credential{}, errkit.New("refusing to store an empty orcarouter credential")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	previous, err := s.readRawLocked()
	if err != nil && !errors.Is(err, ErrNoCredential) {
		return Credential{}, err
	}

	generation := int64(1)
	if previous != nil && previous.Generation >= generation {
		generation = previous.Generation + 1
	}

	stored := storedCredential{
		Key:        credential.Key,
		Scope:      credential.Scope,
		UserID:     credential.UserID,
		Source:     source,
		Generation: generation,
		IssuedAt:   time.Now().UTC(),
	}
	if err := s.writeLocked(stored); err != nil {
		return Credential{}, err
	}

	credential.Source = source
	credential.Generation = generation
	credential.IssuedAt = stored.IssuedAt

	return credential, nil
}

// Clear removes the stored credential, which is how a user logs out.
func (s *CredentialStore) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	err := os.Remove(s.path())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return errkit.Wrap(err, "could not clear the stored orcarouter credential")
	}

	return nil
}

// MarkNeedsReauth marks the credential generation that made a rejected request
// as requiring reauthentication.
//
// The generation is the whole safety property: if the stored generation is no
// longer the one that was rejected, a newer login has already replaced it and
// the late failure must not touch it.
func (s *CredentialStore) MarkNeedsReauth(rejectedGeneration int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.readRawLocked()
	if errors.Is(err, ErrNoCredential) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if stored.Generation != rejectedGeneration {
		// A newer credential is in place; the rejection belongs to the old one.
		return false, nil
	}
	if stored.NeedsReauth && stored.NeedsReauthGeneration == rejectedGeneration {
		return false, nil
	}

	stored.NeedsReauth = true
	stored.NeedsReauthGeneration = rejectedGeneration
	if err := s.writeLocked(*stored); err != nil {
		return false, err
	}

	return true, nil
}

// NeedsReauth reports whether the current credential is marked unusable.
func (s *CredentialStore) NeedsReauth() bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	stored, err := s.readRawLocked()
	if err != nil || stored == nil {
		return false
	}

	return stored.NeedsReauth
}

func (s *CredentialStore) readRawLocked() (*storedCredential, error) {
	raw, err := os.ReadFile(s.path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoCredential
	}
	if err != nil {
		return nil, errkit.Wrap(err, "could not read the stored orcarouter credential")
	}

	var stored storedCredential
	if err := json.Unmarshal(raw, &stored); err != nil {
		return nil, errkit.Wrap(err, "stored orcarouter credential is not valid json")
	}

	return &stored, nil
}

// writeLocked persists the credential atomically with owner-only permissions.
// The directory is created 0700, matching nuclei's other secret material.
func (s *CredentialStore) writeLocked(stored storedCredential) error {
	path := s.path()
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errkit.Wrapf(err, "could not create %q", dir)
	}

	data, err := json.Marshal(stored)
	if err != nil {
		return errkit.Wrap(err, "could not encode the orcarouter credential")
	}

	temp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return errkit.Wrapf(err, "could not create a temporary file in %q", dir)
	}

	tempPath := temp.Name()
	defer func() {
		if temp != nil {
			_ = temp.Close()
		}
		_ = os.Remove(tempPath)
	}()

	if err := temp.Chmod(credentialFileMode); err != nil {
		return errkit.Wrap(err, "could not set credential file permissions")
	}
	if _, err := temp.Write(data); err != nil {
		return errkit.Wrap(err, "could not write the orcarouter credential")
	}
	if err := temp.Sync(); err != nil {
		return errkit.Wrap(err, "could not flush the orcarouter credential")
	}
	if err := temp.Close(); err != nil {
		return errkit.Wrap(err, "could not close the orcarouter credential")
	}

	temp = nil

	if err := os.Rename(tempPath, path); err != nil {
		return errkit.Wrapf(err, "could not replace %q", path)
	}

	return nil
}

// newState returns an unpredictable opaque value for a CSRF state parameter.
func newState() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", errkit.Wrap(err, "could not read from the system random source")
	}

	return hex.EncodeToString(buf), nil
}
