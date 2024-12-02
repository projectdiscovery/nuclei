package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var (
	ErrUnknownAlgorithm = errors.New("unknown algorithm")
	SignaturePattern    = "# digest: "
	SignatureFmt        = SignaturePattern + "%x" + ":%v" // `#digest: <signature>:<fragment>`
)

// ExtractSignatureAndContent extracts the signature (if present) and returns the content without the signature
func ExtractSignatureAndContent(data []byte) (signature, content []byte) {
	dataStr := string(data)
	if idx := strings.LastIndex(dataStr, SignaturePattern); idx != -1 {
		signature = []byte(strings.TrimSpace(dataStr[idx:]))
		content = bytes.TrimSpace(data[:idx])
	} else {
		content = data
	}
	content = bytes.TrimSpace(content)
	return signature, content
}

// SignableTemplate is a template that can be signed
type SignableTemplate interface {
	// GetFileImports returns a list of files that are imported by the template
	GetFileImports() []string
	// HasCodeProtocol returns true if the template has a code protocol section
	HasCodeProtocol() bool
}

type TemplateSigner struct {
	sync.Once
	handler  *KeyHandler
	fragment string
}

// Identifier returns the identifier for the template signer
func (t *TemplateSigner) Identifier() string {
	return t.handler.cert.Subject.CommonName
}

// fragment is optional part of signature that is used to identify the user
// who signed the template via md5 hash of public key
func (t *TemplateSigner) GetUserFragment() string {
	// wrap with sync.Once to reduce unnecessary md5 hashing
	t.Do(func() {
		if t.handler.ecdsaPubKey != nil {
			hashed := md5.Sum(t.handler.ecdsaPubKey.X.Bytes())
			t.fragment = fmt.Sprintf("%x", hashed)
		}
	})
	return t.fragment
}

// Sign signs the given template with the template signer and returns the signature
func (t *TemplateSigner) Sign(data []byte, tmpl SignableTemplate) (string, error) {
	existingSignature, content := ExtractSignatureAndContent(data)

	// while re-signing template check if it has a code protocol
	// if it does then verify that it is signed by current signer
	// if not then return error
	if tmpl.HasCodeProtocol() {
		if len(existingSignature) > 0 {
			arr := strings.SplitN(string(existingSignature), ":", 3)
			if len(arr) == 2 {
				// signature has no fragment
				return "", errorutil.NewWithTag("signer", "re-signing code templates are not allowed for security reasons.")
			}
			if len(arr) == 3 {
				// signature has fragment verify if it is equal to current fragment
				fragment := t.GetUserFragment()
				if fragment != arr[2] {
					return "", errorutil.NewWithTag("signer", "re-signing code templates are not allowed for security reasons.")
				}
			}
		}
	}

	buff := bytes.NewBuffer(content)
	// if file has any imports process them
	for _, file := range tmpl.GetFileImports() {
		bin, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		buff.WriteRune('\n')
		buff.Write(bin)
	}
	signatureData, err := t.sign(buff.Bytes())
	if err != nil {
		return "", err
	}
	return signatureData, nil
}

// Signs given data with the template signer
// Note: this should not be used for signing templates as file references
// in templates are not processed use template.SignTemplate() instead
func (t *TemplateSigner) sign(data []byte) (string, error) {
	dataHash := sha256.Sum256(data)
	ecdsaSignature, err := ecdsa.SignASN1(rand.Reader, t.handler.ecdsaKey, dataHash[:])
	if err != nil {
		return "", err
	}
	var signatureData bytes.Buffer
	if err := gob.NewEncoder(&signatureData).Encode(ecdsaSignature); err != nil {
		return "", err
	}
	return fmt.Sprintf(SignatureFmt, signatureData.Bytes(), t.GetUserFragment()), nil
}

// Verify verifies the given template with the template signer
func (t *TemplateSigner) Verify(data []byte, tmpl SignableTemplate) (bool, error) {
	signature, content := ExtractSignatureAndContent(data)
	if len(signature) == 0 {
		return false, errors.New("no signature found")
	}

	if !bytes.HasPrefix(signature, []byte(SignaturePattern)) {
		return false, errors.New("signature must be at the end of the template")
	}

	digestData := bytes.TrimSpace(bytes.TrimPrefix(signature, []byte(SignaturePattern)))
	// remove fragment from digest as it is used for re-signing purposes only
	digestString := strings.TrimSuffix(string(digestData), ":"+t.GetUserFragment())
	digest, err := hex.DecodeString(digestString)
	if err != nil {
		return false, err
	}

	// normalize content by removing \r\n everywhere since this only done for verification
	// it does not affect the actual template
	content = bytes.ReplaceAll(content, []byte("\r\n"), []byte("\n"))

	buff := bytes.NewBuffer(content)
	// if file has any imports process them
	for _, file := range tmpl.GetFileImports() {
		bin, err := os.ReadFile(file)
		if err != nil {
			return false, err
		}
		buff.WriteRune('\n')
		buff.Write(bin)
	}

	return t.verify(buff.Bytes(), digest)
}

// Verify verifies the given data with the template signer
// Note: this should not be used for verifying templates as file references
// in templates are not processed
func (t *TemplateSigner) verify(data, signatureData []byte) (bool, error) {
	dataHash := sha256.Sum256(data)

	var signature []byte
	if err := gob.NewDecoder(bytes.NewReader(signatureData)).Decode(&signature); err != nil {
		return false, err
	}
	return ecdsa.VerifyASN1(t.handler.ecdsaPubKey, dataHash[:], signature), nil
}

// NewTemplateSigner creates a new signer for signing templates
func NewTemplateSigner(cert, privateKey []byte) (*TemplateSigner, error) {
	handler := &KeyHandler{}
	var err error
	if cert != nil || privateKey != nil {
		handler.UserCert = cert
		handler.PrivateKey = privateKey
	} else {
		err = handler.ReadCert(CertEnvVarName, config.DefaultConfig.GetKeysDir())
		if err == nil {
			err = handler.ReadPrivateKey(PrivateKeyEnvName, config.DefaultConfig.GetKeysDir())
		}
	}
	if err != nil && !SkipGeneratingKeys {
		if err != ErrNoCertificate && err != ErrNoPrivateKey {
			gologger.Info().Msgf("Invalid user cert found : %s\n", err)
		}
		// generating new keys
		handler.GenerateKeyPair()
		if err := handler.SaveToDisk(config.DefaultConfig.GetKeysDir()); err != nil {
			gologger.Fatal().Msgf("could not save generated keys to disk: %s\n", err)
		}
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

// NewTemplateSignerFromFiles creates a new signer for signing templates
func NewTemplateSignerFromFiles(cert, privKey string) (*TemplateSigner, error) {
	certData, err := os.ReadFile(cert)
	if err != nil {
		return nil, err
	}
	privKeyData, err := os.ReadFile(privKey)
	if err != nil {
		return nil, err
	}
	return NewTemplateSigner(certData, privKeyData)
}

// NewTemplateSigVerifier creates a new signer for verifying templates
func NewTemplateSigVerifier(cert []byte) (*TemplateSigner, error) {
	handler := &KeyHandler{}
	if cert != nil {
		handler.UserCert = cert
	} else {
		if err := handler.ReadCert(CertEnvVarName, config.DefaultConfig.GetKeysDir()); err != nil {
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
