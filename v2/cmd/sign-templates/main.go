package main

import (
	"io/fs"
	"log"
	"path/filepath"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
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
		flagSet.StringVarP(&opts.Algorithm, "algorithm", "a", "rsa", "signature algorithm (rsa, ecdsa)"),
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

	algo := signer.ParseAlgorithm(opts.Algorithm)
	if algo == signer.Undefined {
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

		if err := utils.ProcessFile(sign, iterItem); err != nil {
			return err
		}

		return nil
	})
}
