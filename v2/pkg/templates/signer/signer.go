package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"os"

	fileutil "github.com/projectdiscovery/utils/file"
	"golang.org/x/crypto/ssh"
)

type Signer struct {
	options       *Options
	sshSigner     ssh.Signer
	sshVerifier   ssh.PublicKey
	ecdsaSigner   *ecdsa.PrivateKey
	ecdsaVerifier *ecdsa.PublicKey
}

func New(options *Options) (*Signer, error) {
	var (
		privateKeyData, passphraseData, publicKeyData []byte
		err                                           error
	)
	if options.PrivateKeyName != "" {
		privateKeyData, err = readKeyFromFileOrEnv(options.PrivateKeyName)
		if err != nil {
			return nil, err
		}
	} else {
		privateKeyData = options.PrivateKeyData
	}

	if options.PassphraseName != "" {
		passphraseData = readKeyFromFileOrEnvWithDefault(options.PassphraseName, []byte{})
	} else {
		passphraseData = options.PassphraseData
	}

	if options.PublicKeyName != "" {
		publicKeyData, err = readKeyFromFileOrEnv(options.PublicKeyName)
		if err != nil {
			return nil, err
		}
	} else {
		publicKeyData = options.PublicKeyData
	}

	signer := &Signer{options: options}

	switch signer.options.Algorithm {
	case RSA:
		signer.sshSigner, signer.sshVerifier, err = parseRsa(privateKeyData, publicKeyData, passphraseData)
	case ECDSA:
		signer.ecdsaSigner, signer.ecdsaVerifier, err = parseECDSA(privateKeyData, publicKeyData)
	default:
		return nil, ErrUnknownAlgorithm
	}

	if err != nil {
		return nil, err
	}

	return signer, nil
}

func NewVerifier(options *Options) (*Signer, error) {
	var (
		publicKeyData []byte
		err           error
	)
	if options.PublicKeyName != "" {
		publicKeyData, err = readKeyFromFileOrEnv(options.PrivateKeyName)
		if err != nil {
			return nil, err
		}
	} else {
		publicKeyData = options.PublicKeyData
	}

	signer := &Signer{options: options}

	switch signer.options.Algorithm {
	case RSA:
		signer.sshVerifier, err = parseRsaPublicKey(publicKeyData)
	case ECDSA:
		signer.ecdsaVerifier, err = parseECDSAPublicKey(publicKeyData)
	default:
		return nil, ErrUnknownAlgorithm
	}

	if err != nil {
		return nil, err
	}

	return signer, nil
}

func (s *Signer) Sign(data []byte) ([]byte, error) {
	dataHash := sha256.Sum256(data)
	switch s.options.Algorithm {
	case RSA:
		sshSignature, err := s.sshSigner.Sign(rand.Reader, dataHash[:])
		if err != nil {
			return nil, err
		}
		var signatureData bytes.Buffer
		if err := gob.NewEncoder(&signatureData).Encode(sshSignature); err != nil {
			return nil, err
		}
		return signatureData.Bytes(), nil
	case ECDSA:
		r, s, err := ecdsa.Sign(rand.Reader, s.ecdsaSigner, dataHash[:])
		if err != nil {
			return nil, err
		}
		ecdsaSignature := &EcdsaSignature{R: r, S: s}
		var signatureData bytes.Buffer
		if err := gob.NewEncoder(&signatureData).Encode(ecdsaSignature); err != nil {
			return nil, err
		}
		return signatureData.Bytes(), nil
	default:
		return nil, ErrUnknownAlgorithm
	}
}

func (s *Signer) Verify(data, signatureData []byte) (bool, error) {
	dataHash := sha256.Sum256(data)
	switch s.options.Algorithm {
	case RSA:
		signature := &ssh.Signature{}
		if err := gob.NewDecoder(bytes.NewReader(signatureData)).Decode(&signature); err != nil {
			return false, err
		}
		if err := s.sshVerifier.Verify(dataHash[:], signature); err != nil {
			return false, err
		}
		return true, nil
	case ECDSA:
		signature := &EcdsaSignature{}
		if err := gob.NewDecoder(bytes.NewReader(signatureData)).Decode(&signature); err != nil {
			return false, err
		}
		return ecdsa.Verify(s.ecdsaVerifier, dataHash[:], signature.R, signature.S), nil
	default:
		return false, ErrUnknownAlgorithm
	}
}

func parseRsa(privateKeyData, passphraseData, publicKeyData []byte) (ssh.Signer, ssh.PublicKey, error) {
	privateKey, err := parseRsaPrivateKey(privateKeyData, passphraseData)
	if err != nil {
		return nil, nil, err
	}

	publicKey, err := parseRsaPublicKey(publicKeyData)
	if err != nil {
		return nil, nil, err
	}

	return privateKey, publicKey, nil
}

func parseRsaPrivateKey(privateKeyData, passphraseData []byte) (ssh.Signer, error) {
	if len(passphraseData) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(privateKeyData, passphraseData)
	}
	return ssh.ParsePrivateKey(privateKeyData)
}

func parseRsaPublicKey(publicKeyData []byte) (ssh.PublicKey, error) {
	publicKey, _, _, _, err := ssh.ParseAuthorizedKey(publicKeyData)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func parseECDSA(privateKeyData, publicKeyData []byte) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateKey, err := parseECDSAPrivateKey(privateKeyData)
	if err != nil {
		return nil, nil, err
	}
	publicKey, err := parseECDSAPublicKey(publicKeyData)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func parseECDSAPrivateKey(privateKeyData []byte) (*ecdsa.PrivateKey, error) {
	blockPriv, _ := pem.Decode(privateKeyData)
	return x509.ParseECPrivateKey(blockPriv.Bytes)
}

func parseECDSAPublicKey(publicKeyData []byte) (*ecdsa.PublicKey, error) {
	blockPub, _ := pem.Decode(publicKeyData)
	genericPublicKey, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, err
	}
	if publicKey, ok := genericPublicKey.(*ecdsa.PublicKey); ok {
		return publicKey, nil
	}

	return nil, errors.New("couldn't parse ecdsa public key")
}

func readKeyFromFileOrEnvWithDefault(keypath string, defaultValue []byte) []byte {
	keyValue, err := readKeyFromFileOrEnv(keypath)
	if err != nil {
		return defaultValue
	}
	return keyValue
}

func readKeyFromFileOrEnv(keypath string) ([]byte, error) {
	if fileutil.FileExists(keypath) {
		return os.ReadFile(keypath)
	}
	if keydata := os.Getenv(keypath); keydata != "" {
		return []byte(keydata), nil
	}
	return nil, fmt.Errorf("Private key not found in file or environment variable: %s", keypath)
}
