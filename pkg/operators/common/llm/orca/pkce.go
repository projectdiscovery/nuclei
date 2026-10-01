package orca

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/projectdiscovery/utils/errkit"
)

// CodeChallengeMethod is the only method this client sends. S256 is used for
// every flow, including a loopback redirect: the user can always choose "show me
// a code" on the consent screen, which puts the code in human hands, and a
// displayed code must be redeemable only by the process holding the verifier.
const CodeChallengeMethod = "S256"

// PKCE material sizes. The verifier is 32 bytes of cryptographic randomness,
// base64url encoded without padding, which is inside the RFC 7636 range and
// well above the 256-bit entropy a challenge should carry.
const (
	verifierBytes = 32
	stateBytes    = 16

	// maxExchangeBody bounds what a compromised or broken endpoint can make us
	// read from an exchange response.
	maxExchangeBody = 64 << 10
)

// PKCE holds one authorization attempt's secret material.
//
// The verifier must never leave the process except in the code exchange, and
// must never appear in a URL, a log, or an error. Nothing in this type has a
// String method that renders it, so an accidental %v of the struct cannot leak
// it either.
type PKCE struct {
	// Verifier is the secret. It is sent only to the exchange endpoint.
	Verifier string
	// Challenge is base64url(sha256(Verifier)) without padding.
	Challenge string
	// State is the opaque CSRF token echoed back by the consent screen.
	State string
}

// NewPKCE generates fresh PKCE material for one attempt. Every attempt gets new
// material: reusing a verifier, or deriving it from anything guessable, is what
// makes an intercepted code redeemable by someone else.
func NewPKCE() (PKCE, error) {
	verifier, err := randomB64(verifierBytes)
	if err != nil {
		return PKCE{}, err
	}
	state, err := randomB64(stateBytes)
	if err != nil {
		return PKCE{}, err
	}

	return PKCE{
		Verifier:  verifier,
		Challenge: CodeChallenge(verifier),
		State:     state,
	}, nil
}

// CodeChallenge derives the S256 challenge for a verifier.
func CodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// MatchesState compares the echoed state in constant time. A plain != would
// leak the expected value through timing to anything that can drop requests on
// the loopback listener.
func (p PKCE) MatchesState(echoed string) bool {
	return subtle.ConstantTimeCompare([]byte(p.State), []byte(echoed)) == 1
}

// CallbackURL is the literal out-of-band marker. It is spelled out rather than
// omitted so the mode is asked for rather than guessed at.
const CallbackURLOutOfBand = "oob"

// AuthorizeURL builds the consent-screen URL. Only the challenge is placed here;
// the verifier stays in the process.
func AuthorizeURL(authBase, callbackURL string, pkce PKCE, appName, scope string) string {
	query := url.Values{}
	query.Set("callback_url", callbackURL)
	query.Set("code_challenge", pkce.Challenge)
	query.Set("code_challenge_method", CodeChallengeMethod)
	query.Set("state", pkce.State)
	if appName != "" {
		query.Set("app_name", appName)
	}
	if scope != "" {
		query.Set("scope", scope)
	}

	return strings.TrimSuffix(authBase, "/") + AuthPath + "?" + query.Encode()
}

// ExchangeResult is what a successful code exchange returns.
type ExchangeResult struct {
	// Key is the issued OrcaRouter API key.
	Key string `json:"key"`
	// UserID identifies the account the key belongs to.
	UserID string `json:"user_id"`
	// Scope is the scope that was granted, which may be narrower than the one
	// requested.
	Scope string `json:"scope"`
}

// Exchange redeems an authorization code for an API key.
//
// The request goes to the auth origin's /api/v1/auth/keys. It is never sent to
// the inference origin: https://api.orcarouter.ai/v1/auth/keys does not exist.
func Exchange(ctx context.Context, client *http.Client, authBase, code, verifier string) (ExchangeResult, error) {
	if strings.TrimSpace(code) == "" {
		return ExchangeResult{}, &PKCEError{Kind: PKCEErrorRejected, Message: "the authorization code is empty"}
	}
	if strings.TrimSpace(verifier) == "" {
		return ExchangeResult{}, &PKCEError{Kind: PKCEErrorRejected, Message: "the code verifier is empty"}
	}
	if client == nil {
		client = http.DefaultClient
	}

	payload, err := json.Marshal(map[string]string{
		"code":                  strings.TrimSpace(code),
		"code_verifier":         verifier,
		"code_challenge_method": CodeChallengeMethod,
	})
	if err != nil {
		return ExchangeResult{}, errkit.Wrap(err, "could not encode the orcarouter code exchange")
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimSuffix(authBase, "/")+ExchangePath,
		bytes.NewReader(payload),
	)
	if err != nil {
		return ExchangeResult{}, errkit.Wrap(err, "could not build the orcarouter code exchange")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	response, err := client.Do(request)
	if err != nil {
		return ExchangeResult{}, &PKCEError{
			Kind:    PKCEErrorNetwork,
			Message: "could not reach the orcarouter auth endpoint",
			Err:     err,
		}
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, maxExchangeBody))
	if err != nil {
		return ExchangeResult{}, &PKCEError{
			Kind:    PKCEErrorNetwork,
			Message: "could not read the orcarouter code exchange response",
			Err:     err,
		}
	}

	if response.StatusCode != http.StatusOK {
		return ExchangeResult{}, exchangeError(response.StatusCode, body)
	}

	var result ExchangeResult
	if err := json.Unmarshal(body, &result); err != nil {
		return ExchangeResult{}, &PKCEError{
			Kind:    PKCEErrorRejected,
			Message: "the orcarouter code exchange response was not valid json",
			Err:     err,
		}
	}
	if strings.TrimSpace(result.Key) == "" {
		return ExchangeResult{}, &PKCEError{
			Kind:    PKCEErrorRejected,
			Message: "the orcarouter code exchange returned no key",
		}
	}

	// Read the granted scope back. It is what was granted, not what was asked
	// for: a workspace role can narrow it, and a narrower grant must be
	// reported rather than assumed away.
	if result.Scope != "" && result.Scope != ScopeAPI {
		return ExchangeResult{}, &PKCEError{
			Kind: PKCEErrorScopeDowngrade,
			Message: fmt.Sprintf(
				"orcarouter granted scope %q, which is not sufficient for inference (need %q)",
				result.Scope,
				ScopeAPI,
			),
		}
	}

	return result, nil
}

// exchangeError maps an exchange failure status to a typed, actionable error.
func exchangeError(status int, body []byte) error {
	detail := serverMessage(body)

	switch status {
	case http.StatusBadRequest:
		// 400 is a code_challenge_method the server did not recognise, or one
		// that differs from the method sent at authorize time.
		return &PKCEError{
			Kind: PKCEErrorMethodDowngrade,
			Message: "orcarouter rejected the code challenge method (S256); the authorization request and the " +
				"exchange must use the same method" + detail,
		}
	case http.StatusForbidden:
		// 403 covers an unknown, expired or already-used code, and a verifier
		// that does not match the stored challenge. All are terminal for this
		// attempt.
		return &PKCEError{
			Kind: PKCEErrorRejected,
			Message: "orcarouter rejected the authorization code (unknown, expired, already used, or the " +
				"verifier did not match); start the login again" + detail,
		}
	case http.StatusTooManyRequests:
		return &PKCEError{
			Kind: PKCEErrorRateLimited,
			Message: "orcarouter refused to issue another key (limit is 10 PKCE keys per user per 24 hours); " +
				"reuse the stored credential or wait before logging in again" + detail,
		}
	default:
		return &PKCEError{
			Kind:    PKCEErrorRejected,
			Message: fmt.Sprintf("orcarouter code exchange failed with status %d%s", status, detail),
		}
	}
}

// serverMessage extracts a bounded human-readable message from an error body.
// Error bodies from the auth endpoints are {"error":...,"error_description":...}
// rather than the relay's usual envelope.
func serverMessage(body []byte) string {
	var parsed struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil {
		message := strings.TrimSpace(parsed.Error)
		if description := strings.TrimSpace(parsed.Description); description != "" {
			if message != "" {
				message += ": " + description
			} else {
				message = description
			}
		}
		if message != "" {
			return ": " + truncate(message, 200)
		}

		return ""
	}

	text := strings.TrimSpace(string(body))
	if text == "" {
		return ""
	}

	return ": " + truncate(text, 200)
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}

	return value[:limit] + "..."
}

func randomB64(size int) (string, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return "", errkit.Wrap(err, "could not read from the system random source")
	}

	return base64.RawURLEncoding.EncodeToString(buf), nil
}
