package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	"golang.org/x/term"
)

const (
	PrivateKeyEnvVarName = "NUCLEI_SIGNATURE_PRIVATE_KEY"
	PublicKeyEnvVarName  = "NUCLEI_SIGNATURE_PUBLIC_KEY"
	AlgorithmEnvVarName  = "NUCLEI_SIGNATURE_ALGORITHM"
)

const (
	// we intentionally choose these names to avoid confusion and highlight usecase
	PrivateKeyFileName = "nuclei-template-signer"
	PublicKeyFileName  = "nuclei-template-signer.pub"
	AlgoFileName       = "nuclei-template-signer.algo"
)

var DefaultVerifiers []*Signer

func init() {
	// add default pd verifier
	if verifier, err := NewVerifier(&Options{PublicKeyData: pdPublicKey, Algorithm: RSA}); err == nil {
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

// GetSigerKeysOrGenerate returns the key if exist or generates new keys
func GetSigerKeysOrGenerate() *Options {
	// get keys from env or config directory
	keys, err := getKeys(true)
	if err == nil {
		return keys
	}
	gologger.Warning().Msgf("failed to load template signer keys from environment or config directory: %s\n", err)
	// generate new keys
	return generateKeyPair()
}

// GetSignerVerifyOptions gets signer options from environment variables or config directory
// note: this does not load private key
func GetSignerVerifyOptions() (*Options, error) {
	return getKeys(false)
}

// getKeysOrGenerate returns the keys from the environment variables
// or nuclei config directory if they are present
func getKeys(requirePrivateKey bool) (*Options, error) {
	// GET KEYS FROM ENV
	keys := getKeysFromEnv()
	// validate keys from env
	if keys.HasPublicKey() && keys.HasPrivateKey() {
		return keys, nil
	} else if keys.HasPublicKey() && !keys.HasPrivateKey() && !requirePrivateKey {
		return keys, nil
	}
	// fallback to load keys from config directory
	keys = getKeysFromConfigDir()
	// validate keys from config directory
	if keys.HasPublicKey() && keys.HasPrivateKey() {
		return keys, nil
	} else if keys.HasPublicKey() && !keys.HasPrivateKey() && !requirePrivateKey {
		return keys, nil
	}

	return nil, errorutil.New("template signer keys not found use -sign to generate new keys")
}

func getKeysFromEnv() *Options {
	privKey := getDataFromEnv(PrivateKeyEnvVarName)
	pubKey := getDataFromEnv(PublicKeyEnvVarName)
	algo := os.Getenv(AlgorithmEnvVarName)

	return &Options{
		PrivateKeyData: privKey,
		PublicKeyData:  pubKey,
		Algorithm:      ParseAlgorithm(algo),
	}
}

func getKeysFromConfigDir() *Options {
	opts := &Options{}
	cfgdir := config.DefaultConfig.GetConfigDir()

	if fileutil.FileExists(filepath.Join(cfgdir, PrivateKeyFileName)) {
		opts.PrivateKeyName = filepath.Join(cfgdir, PrivateKeyFileName)
	}
	if fileutil.FileExists(filepath.Join(cfgdir, PublicKeyFileName)) {
		opts.PublicKeyName = filepath.Join(cfgdir, PublicKeyFileName)
	}
	if fileutil.FileExists(filepath.Join(cfgdir, AlgoFileName)) {
		opts.Algorithm = ParseAlgorithm(string(getDataFromFile(filepath.Join(cfgdir, AlgoFileName))))
	}
	return opts
}

func generateKeyPair() *Options {
	gologger.Info().Msgf("Generating new key-pair for signing code templates")
	fmt.Printf("[*] Enter passphrase (exit to abort): ")
	passphrase := getPassphrase()

	// generate new key-pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		gologger.Fatal().Msgf("failed to generate ecdsa key-pair: %s", err)
	}
	privateKeyData, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		gologger.Fatal().Msgf("failed to marshal ecdsa private key: %s", err)
	}
	publicKeyData, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		gologger.Fatal().Msgf("failed to marshal ecdsa public key: %s", err)
	}

	//  pem encode keys
	pemBlock := &pem.Block{
		Type: "EC PRIVATE KEY", Bytes: privateKeyData,
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
	publicKeyPem := &pem.Block{
		Type: "PUBLIC KEY", Bytes: publicKeyData,
	}

	// write keys to config directory
	cfgdir := config.DefaultConfig.GetConfigDir()
	if err := os.WriteFile(filepath.Join(cfgdir, PrivateKeyFileName), pem.EncodeToMemory(pemBlock), 0600); err != nil {
		gologger.Fatal().Msgf("failed to write private key: %s", err)
	}
	if err := os.WriteFile(filepath.Join(cfgdir, PublicKeyFileName), pem.EncodeToMemory(publicKeyPem), 0600); err != nil {
		gologger.Fatal().Msgf("failed to write public key: %s", err)
	}
	if err := os.WriteFile(filepath.Join(cfgdir, AlgoFileName), []byte("ecdsa"), 0600); err != nil {
		gologger.Fatal().Msgf("failed to write algorithm: %s", err)
	}
	gologger.Info().Msgf("Successfully generated new key-pair for signing code templates")

	return &Options{
		PrivateKeyData: pem.EncodeToMemory(pemBlock),
		PublicKeyData:  pem.EncodeToMemory(publicKeyPem),
		PassphraseData: passphrase,
		Algorithm:      ECDSA,
	}
}

// getDataFromFile returns the data from the file
func getDataFromFile(fileName string) []byte {
	bin, _ := os.ReadFile(fileName)
	return bin
}

func getDataFromEnv(envName string) []byte {
	data := os.Getenv(envName)
	if data == "" {
		return nil
	}
	if fileutil.FileExists(data) {
		bin, _ := os.ReadFile(data)
		return bin
	} else {
		return []byte(data)
	}
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
