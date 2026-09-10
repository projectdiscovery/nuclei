package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

const (
	caCertFileName = "dast-proxy-ca.pem"
	caKeyFileName  = "dast-proxy-ca.key"

	caValidity = 2 * 365 * 24 * time.Hour

	// The key can mint a certificate that the user's browser trusts for any
	// host, so it must never be readable by other accounts on the machine.
	caKeyFileMode  os.FileMode = 0o600
	caCertFileMode os.FileMode = 0o644
)

// CA is the certificate authority used to sign intercepted TLS connections.
type CA struct {
	Certificate *tls.Certificate
	CertPath    string
	CertPEM     []byte
}

// LoadOrCreateCA loads the interception CA from dir, generating and persisting
// a new one on first use.
//
// goproxy ships a built-in CA whose private key is published with the library;
// it is deliberately never used here. A per-installation key is the only thing
// stopping a third party from minting certificates the user already trusts.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, caCertFileName)
	keyPath := filepath.Join(dir, caKeyFileName)

	if fileutil.FileExists(certPath) && fileutil.FileExists(keyPath) {
		return loadCA(certPath, keyPath)
	}
	return createCA(dir, certPath, keyPath)
}

func loadCA(certPath, keyPath string) (*CA, error) {
	if err := verifyKeyPermissions(keyPath); err != nil {
		return nil, err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not read dast proxy CA certificate")
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, errors.Wrap(err, "could not read dast proxy CA key")
	}

	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse dast proxy CA keypair")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return nil, errors.Wrap(err, "could not parse dast proxy CA certificate")
	}
	if !leaf.IsCA {
		return nil, errors.Errorf("%s is not a certificate authority", certPath)
	}
	// Regenerating silently would swap the CA out from under a certificate the
	// user has already installed and trusted, so this is left to the user.
	if time.Now().After(leaf.NotAfter) {
		return nil, errors.Errorf("dast proxy CA expired on %s, remove %s and %s to generate a new one",
			leaf.NotAfter.Format(time.RFC3339), certPath, keyPath)
	}
	certificate.Leaf = leaf

	return &CA{Certificate: &certificate, CertPath: certPath, CertPEM: certPEM}, nil
}

func createCA(dir, certPath, keyPath string) (*CA, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, errors.Wrap(err, "could not create dast proxy CA directory")
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "could not generate dast proxy CA key")
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, errors.Wrap(err, "could not generate dast proxy CA serial number")
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "Nuclei DAST Proxy CA",
			Organization: []string{"ProjectDiscovery"},
		},
		NotBefore:             now.Add(-1 * time.Hour), // tolerate clock skew on the client
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		// Sign leaf certificates only: a CA reachable through this one must not
		// be able to issue further authorities.
		MaxPathLen:     0,
		MaxPathLenZero: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not create dast proxy CA certificate")
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal dast proxy CA key")
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// O_EXCL so a pre-existing path, including a symlink planted by another
	// user, can never be written through.
	if err := writeNewFile(keyPath, keyPEM, caKeyFileMode); err != nil {
		return nil, errors.Wrap(err, "could not write dast proxy CA key")
	}
	if err := writeNewFile(certPath, certPEM, caCertFileMode); err != nil {
		return nil, errors.Wrap(err, "could not write dast proxy CA certificate")
	}

	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.Wrap(err, "could not parse generated dast proxy CA certificate")
	}
	return &CA{
		Certificate: &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf},
		CertPath:    certPath,
		CertPEM:     certPEM,
	}, nil
}

func writeNewFile(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func verifyKeyPermissions(keyPath string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	info, err := os.Stat(keyPath)
	if err != nil {
		return errors.Wrap(err, "could not stat dast proxy CA key")
	}
	if mode := info.Mode().Perm(); mode&0o077 != 0 {
		return errors.Errorf("dast proxy CA key %s is readable by other users (%#o), run: chmod 600 %s",
			keyPath, mode, keyPath)
	}
	return nil
}
