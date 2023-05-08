package signer

import (
	"errors"
	"regexp"
	"strings"
)

type AlgorithmType uint8

const (
	RSA AlgorithmType = iota
	ECDSA
	Undefined
)

func ParseAlgorithm(algorithm string) (AlgorithmType, error) {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	switch algorithm {
	case "ecdsa":
		return ECDSA, nil
	case "rsa":
		return RSA, nil
	default:
		return Undefined, nil
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

var (
	ReDigest            = regexp.MustCompile(`(?m)^#\sdigest:\s.+$`)
	ErrUnknownAlgorithm = errors.New("unknown algorithm")
)
