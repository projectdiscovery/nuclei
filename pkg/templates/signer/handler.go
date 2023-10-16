package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/rs/xid"
	"golang.org/x/term"
)

const (
	CertType           = "PD NUCLEI USER CERTIFICATE"
	PrivateKeyType     = "PD NUCLEI USER PRIVATE KEY"
	CertFilename       = "nuclei-user.crt"
	PrivateKeyFilename = "nuclei-user-private-key.pem"
	CertEnvVarName     = "NUCLEI_USER_CERTIFICATE"
	PrivateKeyEnvName  = "NUCLEI_USER_PRIVATE_KEY"
)

var (
	ErrNoCertificate   = fmt.Errorf("nuclei user certificate not found")
	ErrNoPrivateKey    = fmt.Errorf("nuclei user private key not found")
	SkipGeneratingKeys = false
	noUserPassphrase   = false
)

// KeyHandler handles the key generation and management
// of signer public and private keys
type KeyHandler struct {
	UserCert    []byte
	PrivateKey  []byte
	cert        *x509.Certificate
	ecdsaPubKey *ecdsa.PublicKey
	ecdsaKey    *ecdsa.PrivateKey
}

// ReadUserCert reads the user certificate from environment variable or given directory
func (k *KeyHandler) ReadCert(envName, dir string) error {
	// read from env
	if cert := k.getEnvContent(envName); cert != nil {
		k.UserCert = cert
		return nil
	}
	// read from disk
	if cert, err := os.ReadFile(filepath.Join(dir, CertFilename)); err == nil {
		k.UserCert = cert
		return nil
	}
	return ErrNoCertificate
}

// ReadPrivateKey reads the private key from environment variable or given directory
func (k *KeyHandler) ReadPrivateKey(envName, dir string) error {
	// read from env
	if privateKey := k.getEnvContent(envName); privateKey != nil {
		k.PrivateKey = privateKey
		return nil
	}
	// read from disk
	if privateKey, err := os.ReadFile(filepath.Join(dir, PrivateKeyFilename)); err == nil {
		k.PrivateKey = privateKey
		return nil
	}
	return ErrNoPrivateKey
}

// ParseUserCert parses the user certificate and returns the public key
func (k *KeyHandler) ParseUserCert() error {
	block, _ := pem.Decode(k.UserCert)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if cert.Subject.CommonName == "" {
		return fmt.Errorf("invalid certificate: expected common name to be set")
	}
	k.cert = cert
	var ok bool
	k.ecdsaPubKey, ok = cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("failed to parse ecdsa public key from cert")
	}
	return nil
}

// ParsePrivateKey parses the private key and returns the private key
func (k *KeyHandler) ParsePrivateKey() error {
	block, _ := pem.Decode(k.PrivateKey)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block containing the private key")
	}
	// if pem block is encrypted , decrypt it
	if x509.IsEncryptedPEMBlock(block) { // nolint: all
		gologger.Info().Msgf("Private Key is encrypted with passphrase")
		fmt.Printf("[*] Enter passphrase (exit to abort): ")
		bin, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return err
		}
		fmt.Println()
		if string(bin) == "exit" {
			return fmt.Errorf("private key requires passphrase, but none was provided")
		}
		block.Bytes, err = x509.DecryptPEMBlock(block, bin) // nolint: all
		if err != nil {
			return err
		}
	}
	var err error
	k.ecdsaKey, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	return nil
}

// GenerateKeyPair generates a new key-pair for signing code templates
func (k *KeyHandler) GenerateKeyPair() {

	gologger.Info().Msgf("Generating new key-pair for signing templates")
	fmt.Printf("[*] Enter User/Organization Name (exit to abort) : ")

	// get user/organization name
	identifier := ""
	_, err := fmt.Scanln(&identifier)
	if err != nil {
		gologger.Fatal().Msgf("failed to read user/organization name: %s", err)
	}
	if identifier == "exit" {
		gologger.Fatal().Msgf("exiting key-pair generation")
	}
	if identifier == "" {
		gologger.Fatal().Msgf("user/organization name cannot be empty")
	}

	// generate new key-pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		gologger.Fatal().Msgf("failed to generate ecdsa key-pair: %s", err)
	}

	// create x509 certificate with user/organization name and public key
	// self-signed certificate with generated private key
	k.UserCert, err = k.generateCertWithKey(identifier, privateKey)
	if err != nil {
		gologger.Fatal().Msgf("failed to create certificate: %s", err)
	}

	// marshal private key
	k.PrivateKey, err = k.marshalPrivateKey(privateKey)
	if err != nil {
		gologger.Fatal().Msgf("failed to marshal ecdsa private key: %s", err)
	}
	gologger.Info().Msgf("Successfully generated new key-pair for signing templates")
}

// SaveToDisk saves the generated key-pair to the given directory
func (k *KeyHandler) SaveToDisk(dir string) error {
	_ = fileutil.FixMissingDirs(filepath.Join(dir, CertFilename)) // not required but just in case will take care of missing dirs in path
	if err := os.WriteFile(filepath.Join(dir, CertFilename), k.UserCert, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, PrivateKeyFilename), k.PrivateKey, 0600); err != nil {
		return err
	}
	return nil
}

// getEnvContent returns the content of the environment variable
// if it is a file then it loads its content
func (k *KeyHandler) getEnvContent(name string) []byte {
	val := os.Getenv(name)
	if val == "" {
		return nil
	}
	if fileutil.FileExists(val) {
		data, err := os.ReadFile(val)
		if err != nil {
			gologger.Fatal().Msgf("failed to read file: %s", err)
		}
		return data
	}
	return []byte(val)
}

// generateCertWithKey creates a self-signed certificate with the given identifier and private key
func (k *KeyHandler) generateCertWithKey(identifier string, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	// Setting up the certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(4 * 365 * 24 * time.Hour)

	serialNumber := big.NewInt(xid.New().Time().Unix())
	// create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: identifier,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		NotBefore:          notBefore,
		NotAfter:           notAfter,
		PublicKey:          &privateKey.PublicKey,
		KeyUsage:           x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		IsCA:                  false,
		BasicConstraintsValid: true,
	}
	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}

	var certOut bytes.Buffer
	if err := pem.Encode(&certOut, &pem.Block{Type: CertType, Bytes: derBytes}); err != nil {
		return nil, err
	}
	return certOut.Bytes(), nil
}

// marshalPrivateKey marshals the private key and encrypts it with the given passphrase
func (k *KeyHandler) marshalPrivateKey(privateKey *ecdsa.PrivateKey) ([]byte, error) {

	var passphrase []byte
	// get passphrase to encrypt private key before saving to disk
	if !noUserPassphrase {
		fmt.Printf("[*] Enter passphrase (exit to abort): ")
		passphrase = getPassphrase()
	}

	// marshal private key
	privateKeyData, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		gologger.Fatal().Msgf("failed to marshal ecdsa private key: %s", err)
	}
	//  pem encode keys
	pemBlock := &pem.Block{
		Type: PrivateKeyType, Bytes: privateKeyData,
	}
	// encrypt private key if passphrase is provided
	if len(passphrase) > 0 {
		// encode it with passphrase
		// this function is deprecated since go 1.16 but go stdlib does not want to provide any alternative
		// see: https://github.com/golang/go/issues/8860
		encBlock, err := x509.EncryptPEMBlock(rand.Reader, pemBlock.Type, pemBlock.Bytes, passphrase, x509.PEMCipherAES256) // nolint: all
		if err != nil {
			gologger.Fatal().Msgf("failed to encrypt private key: %s", err)
		}
		pemBlock = encBlock
	}
	return pem.EncodeToMemory(pemBlock), nil
}

func getPassphrase() []byte {
	bin, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		gologger.Fatal().Msgf("could not read passphrase: %s", err)
	}
	fmt.Println()
	if string(bin) == "exit" {
		gologger.Fatal().Msgf("exiting")
	}
	fmt.Printf("[*] Enter same passphrase again: ")
	bin2, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		gologger.Fatal().Msgf("could not read passphrase: %s", err)
	}
	fmt.Println()
	// review: should we allow empty passphrase?
	// we currently allow empty passphrase
	if string(bin) != string(bin2) {
		gologger.Fatal().Msgf("passphrase did not match try again")
	}
	return bin
}
