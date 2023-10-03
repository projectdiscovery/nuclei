package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"errors"
	"os"
	"regexp"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
)

var (
	ReDigest            = regexp.MustCompile(`(?m)^#\sdigest:\s.+$`)
	ErrUnknownAlgorithm = errors.New("unknown algorithm")
)

type TemplateSigner struct {
	handler *KeyHandler
}

// Identifier returns the identifier for the template signer
func (t *TemplateSigner) Identifier() string {
	return t.handler.cert.Subject.CommonName
}

// Signs given data with the template signer
// Note: this should not be used for signing templates as file references
// in templates are not processed use template.SignTemplate() instead
func (t *TemplateSigner) Sign(data []byte) ([]byte, error) {
	dataHash := sha256.Sum256(data)
	ecdsaSignature, err := ecdsa.SignASN1(rand.Reader, t.handler.ecdsaKey, dataHash[:])
	if err != nil {
		return nil, err
	}
	var signatureData bytes.Buffer
	if err := gob.NewEncoder(&signatureData).Encode(ecdsaSignature); err != nil {
		return nil, err
	}
	return signatureData.Bytes(), nil
}

// Verify verifies the given data with the template signer
// Note: this should not be used for verifying templates as file references
// in templates are not processed
func (t *TemplateSigner) Verify(data, signatureData []byte) (bool, error) {
	dataHash := sha256.Sum256(data)

	var signature []byte
	if err := gob.NewDecoder(bytes.NewReader(signatureData)).Decode(&signature); err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(t.handler.ecdsaPubKey, dataHash[:], signature), nil
}

// NewTemplateSignerForSigning creates a new signer for signing templates
func NewTemplateSignerForSigning(cert, privateKey []byte) (*TemplateSigner, error) {
	handler := &KeyHandler{}
	var err error
	if cert != nil || privateKey != nil {
		handler.UserCert = cert
		handler.PrivateKey = privateKey
	} else {
		err = handler.ReadCert(CertEnvVarName, config.DefaultConfig.GetConfigDir())
		if err == nil {
			err = handler.ReadPrivateKey(PrivateKeyEnvName, config.DefaultConfig.GetConfigDir())
		}
	}
	if err != nil && !SkipGeneratingKeys {
		gologger.Info().Msgf("Key-pair not found or invalid, generating new key-pair")
		// generating new keys
		handler.GenerateKeyPair()
		// do not continue further let user re-run the command
		os.Exit(0)
	} else if err != nil && SkipGeneratingKeys {
		return nil, err
	}

	if err := handler.ParseUserCert(); err != nil {
		return nil, err
	}
	if err := handler.ParsePrivateKey(); err != nil {
		return nil, err
	}
	return &TemplateSigner{
		handler: handler,
	}, nil
}

// NewTemplateSignerForVerifying creates a new signer for verifying templates
func NewTemplateSignerForVerifying(cert []byte) (*TemplateSigner, error) {
	handler := &KeyHandler{}
	if cert != nil {
		handler.UserCert = cert
	} else {
		if err := handler.ReadCert(CertEnvVarName, config.DefaultConfig.GetConfigDir()); err != nil {
			return nil, err
		}
	}
	if err := handler.ParseUserCert(); err != nil {
		return nil, err
	}
	return &TemplateSigner{
		handler: handler,
	}, nil
}
