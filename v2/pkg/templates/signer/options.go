package signer

import (
	"strings"
)

type AlgorithmType uint8

const (
	RSA AlgorithmType = iota
	ECDSA
	Undefined
)

func ParseAlgorithm(algorithm string) AlgorithmType {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	switch algorithm {
	case "ecdsa":
		return ECDSA
	case "rsa":
		return RSA
	default:
		return Undefined
	}
}

type Options struct {
	PrivateKeyName string
	PrivateKeyData []byte
	PassphraseName string
	PassphraseData []byte
	PublicKeyName  string
	PublicKeyData  []byte
	Algorithm      AlgorithmType
}

// HasPublicKey returns true if the options has a public key and algorithm
func (o *Options) HasPublicKey() bool {
	if o.Algorithm == Undefined {
		return false
	}
	if o.PublicKeyName != "" || len(o.PublicKeyData) > 0 {
		return true
	}
	return false
}

// HasPrivateKey returns true if the options has a private key and algorithm
func (o *Options) HasPrivateKey() bool {
	if o.Algorithm == Undefined {
		return false
	}
	if o.PrivateKeyName != "" || len(o.PrivateKeyData) > 0 {
		return true
	}
	return false
}
