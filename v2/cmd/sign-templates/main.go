package main

import (
	"io/fs"
	"log"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/extensions"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/signer"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

type options struct {
	Templates            goflags.StringSlice
	Algorithm            string
	PrivateKeyName       string
	PrivateKeyPassPhrase string
	PublicKeyName        string
}

func ParseOptions() (*options, error) {
	opts := &options{}
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`sign-templates is a utility to perform template signature`)

	flagSet.CreateGroup("sign", "sign",
		flagSet.StringSliceVarP(&opts.Templates, "templates", "t", nil, "templates files/folders to sign", goflags.CommaSeparatedStringSliceOptions),
		flagSet.StringVarP(&opts.Algorithm, "algorithm", "a", "ecdsa", "signature algorithm (ecdsa, rsa)"),
		flagSet.StringVarP(&opts.PrivateKeyName, "private-key", "prk", "", "private key env var name or file location"),
		flagSet.StringVarP(&opts.PrivateKeyPassPhrase, "private-key-pass", "prkp", "", "private key passphrase env var name or file location"),
		flagSet.StringVarP(&opts.PublicKeyName, "public-key", "puk", "", "public key env var name or file location"),
	)

	if err := flagSet.Parse(); err != nil {
		return nil, err
	}

	return opts, nil
}

func main() {
	opts, err := ParseOptions()
	if err != nil {
		log.Fatalf("couldn't parse options: %s\n", err)
	}

	var algo signer.AlgorithmType
	switch opts.Algorithm {
	case "rsa":
		algo = signer.RSA
	case "ecdsa":
		algo = signer.ECDSA
	default:
		log.Fatal("unknown algorithm type")
	}

	signerOptions := &signer.Options{
		PrivateKeyName: opts.PrivateKeyName,
		PassphraseName: opts.PrivateKeyPassPhrase,
		PublicKeyName:  opts.PublicKeyName,
		Algorithm:      algo,
	}
	sign, err := signer.New(signerOptions)
	if err != nil {
		log.Fatalf("couldn't create crypto engine: %s\n", err)
	}

	for _, templateItem := range opts.Templates {
		if err := processItem(sign, templateItem); err != nil {
			log.Fatalf("Could not walk directory: %s\n", err)
		}
	}
}

func processItem(sign *signer.Signer, item string) error {
	return filepath.WalkDir(item, func(iterItem string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		if err := processFile(sign, iterItem); err != nil {
			return err
		}

		return nil
	})
}

func processFile(sign *signer.Signer, filePath string) error {
	ext := filepath.Ext(filePath)
	if !stringsutil.EqualFoldAny(ext, extensions.YAML) {
		return nil
	}
	err := signTemplate(sign, filePath)
	if err != nil {
		return errors.Wrapf(err, "could not sign template: %s", filePath)
	}

	ok, err := verifyTemplateSignature(sign, filePath)
	if err != nil {
		return errors.Wrapf(err, "could not verify template: %s", filePath)
	}
	if !ok {
		return errors.Wrapf(err, "template signature doesn't match: %s", filePath)
	}

	return nil
}

func appendToFile(path string, data []byte, digest string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return err
	}

	if _, err := file.WriteString("\n" + digest); err != nil {
		return err
	}
	return nil
}

func signTemplate(sign *signer.Signer, templatePath string) error {
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	signatureData, err := signer.Sign(sign, templateData)
	if err != nil {
		return err
	}
	dataWithoutSignature := signer.RemoveSignatureFromData(templateData)
	return appendToFile(templatePath, dataWithoutSignature, signatureData)
}

func verifyTemplateSignature(sign *signer.Signer, templatePath string) (bool, error) {
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return false, err
	}
	return signer.Verify(sign, templateData)
}
