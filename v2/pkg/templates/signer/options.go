package signer

import (
	"errors"
	"math/big"
	"regexp"
)

type AlgorithmType uint8

const (
	RSA AlgorithmType = iota
	ECDSA
)

type Options struct {
	PrivateKeyName string
	PrivateKeyData []byte
	PassphraseName string
	PassphraseData []byte
	PublicKeyName  string
	PublicKeyData  []byte
	Algorithm      AlgorithmType
}

type EcdsaSignature struct {
	R *big.Int
	S *big.Int
}

var (
	ReDigest            = regexp.MustCompile(`(?m)^#\sdigest:\s.+$`)
	ErrUnknownAlgorithm = errors.New("unknown algorithm")
)
