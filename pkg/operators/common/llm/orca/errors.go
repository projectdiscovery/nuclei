package orca

import (
	"errors"
	"fmt"
)

// PKCEErrorKind classifies a connect-flow failure so callers and tests can act
// on it instead of matching message text.
type PKCEErrorKind string

const (
	// PKCEErrorDenied means the user declined on the consent screen.
	PKCEErrorDenied PKCEErrorKind = "access_denied"
	// PKCEErrorStateMismatch means the callback carried a state this attempt did
	// not issue. The code is discarded without being redeemed.
	PKCEErrorStateMismatch PKCEErrorKind = "state_mismatch"
	// PKCEErrorTimeout means the authorization window closed with no answer.
	PKCEErrorTimeout PKCEErrorKind = "timeout"
	// PKCEErrorCanceled means the caller stopped the attempt.
	PKCEErrorCanceled PKCEErrorKind = "canceled"
	// PKCEErrorRejected means the code was unknown, expired, already used, or
	// the verifier did not match.
	PKCEErrorRejected PKCEErrorKind = "rejected"
	// PKCEErrorMethodDowngrade means the server refused the code challenge
	// method, which is the defence against a downgrade to plain.
	PKCEErrorMethodDowngrade PKCEErrorKind = "method_downgrade"
	// PKCEErrorScopeDowngrade means the granted scope is narrower than the one
	// inference needs.
	PKCEErrorScopeDowngrade PKCEErrorKind = "scope_downgrade"
	// PKCEErrorRateLimited means the per-user PKCE key issuance cap was hit.
	PKCEErrorRateLimited PKCEErrorKind = "rate_limited"
	// PKCEErrorNetwork means the auth endpoint could not be reached or its
	// response could not be read.
	PKCEErrorNetwork PKCEErrorKind = "network"
	// PKCEErrorListener means the loopback callback listener could not be
	// started, so the caller should fall back to the out-of-band flow.
	PKCEErrorListener PKCEErrorKind = "listener"
)

// PKCEError is a typed connect-flow failure.
//
// The Message never contains the verifier, the authorization code, or the issued
// key: those are the values that must not reach a log, an error report or a
// screenshot.
type PKCEError struct {
	Kind    PKCEErrorKind
	Message string
	Err     error
}

// Error implements error.
func (e *PKCEError) Error() string {
	if e == nil {
		return ""
	}
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}

	return e.Message
}

// Unwrap exposes the transport error, if any.
func (e *PKCEError) Unwrap() error {
	if e == nil {
		return nil
	}

	return e.Err
}

// Is makes errors.Is work on the kind.
func (e *PKCEError) Is(target error) bool {
	var other *PKCEError
	if !errors.As(target, &other) {
		return false
	}

	return other.Kind == e.Kind
}

// NewPKCEError builds a typed error without a wrapped cause.
func NewPKCEError(kind PKCEErrorKind, message string) *PKCEError {
	return &PKCEError{Kind: kind, Message: message}
}

// DescribePKCEError renders an actionable line for the user, including the
// console URL when the fix is to revoke or reissue a key.
func DescribePKCEError(err error) string {
	var pkceErr *PKCEError
	if !errors.As(err, &pkceErr) {
		return err.Error()
	}

	hint := ""
	switch pkceErr.Kind {
	case PKCEErrorDenied:
		hint = "you declined the authorization; nothing was stored"
	case PKCEErrorRateLimited:
		hint = "revoke unused keys at " + ConsoleURL
	case PKCEErrorRejected, PKCEErrorScopeDowngrade:
		hint = "manage access at " + ConsoleURL
	case PKCEErrorListener:
		hint = "the out-of-band flow will be used instead"
	case PKCEErrorStateMismatch:
		hint = "the response did not belong to this login attempt; nothing was stored"
	case PKCEErrorTimeout:
		hint = "the authorization window closed; start the login again"
	case PKCEErrorCanceled:
		hint = "login canceled"
	}
	if hint == "" {
		return pkceErr.Error()
	}

	return fmt.Sprintf("%s (%s)", pkceErr.Error(), hint)
}
