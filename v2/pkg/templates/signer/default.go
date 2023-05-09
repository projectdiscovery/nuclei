package signer

import (
	"errors"
)

var DefaultVerifiers []*Signer

func init() {
	// add default pd verifier
	if verifier, err := NewVerifier(&Options{PublicKeyData: pdPublicKey, Algorithm: ECDSA}); err == nil {
		DefaultVerifiers = append(DefaultVerifiers, verifier)
	}
}

func AddToDefault(s *Signer) error {
	if s == nil {
		return errors.New("signer is nil")
	}

	DefaultVerifiers = append(DefaultVerifiers, s)
	return nil
}
