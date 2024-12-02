package main

import (
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"os"
	"path/filepath"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/gologger/levels"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
)

var (
	appConfigDir    = folderutil.AppConfigDirOrDefault(".config", "nuclei")
	defaultCertFile = filepath.Join(appConfigDir, "keys", "nuclei-user.crt")
	defaultPrivKey  = filepath.Join(appConfigDir, "keys", "nuclei-user-private-key.pem")
)

var (
	template string
	cert     string
	privKey  string
)

func main() {
	flag.StringVar(&template, "template", "", "template to sign (file only)")
	flag.StringVar(&cert, "cert", defaultCertFile, "certificate file")
	flag.StringVar(&privKey, "priv-key", defaultPrivKey, "private key file")
	flag.Parse()

	config.DefaultConfig.LogAllEvents = true
	gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose)

	if template == "" {
		gologger.Fatal().Msg("template is required")
	}
	if !fileutil.FileExists(template) {
		gologger.Fatal().Msgf("template file %s does not exist or not a file", template)
	}

	// get signer
	tmplSigner, err := signer.NewTemplateSignerFromFiles(cert, privKey)
	if err != nil {
		gologger.Fatal().Msgf("failed to create signer: %s", err)
	}
	gologger.Info().Msgf("Template Signer: %v\n", tmplSigner.Identifier())

	// read file
	bin, err := os.ReadFile(template)
	if err != nil {
		gologger.Fatal().Msgf("failed to read template file %s: %s", template, err)
	}

	// extract signature and content
	sig, content := signer.ExtractSignatureAndContent(bin)
	hash := sha256.Sum256(content)

	gologger.Info().Msgf("Signature Details:")
	gologger.Info().Msgf("----------------")
	gologger.Info().Msgf("Signature: %s", sig)
	gologger.Info().Msgf("Content Hash (SHA256): %s\n", hex.EncodeToString(hash[:]))

	execOpts := defaultExecutorOpts(template)

	tmpl, err := templates.Parse(template, nil, execOpts)
	if err != nil {
		gologger.Fatal().Msgf("failed to parse template: %s", err)
	}
	gologger.Info().Msgf("Template Verified: %v\n", tmpl.Verified)

	if !tmpl.Verified {
		gologger.Info().Msgf("------------------------")
		gologger.Info().Msg("Template is not verified, signing template")
		if err := templates.SignTemplate(tmplSigner, template); err != nil {
			gologger.Fatal().Msgf("Failed to sign template: %s", err)
		}
		// verify again by reading file what the new signature and hash is
		bin2, err := os.ReadFile(template)
		if err != nil {
			gologger.Fatal().Msgf("failed to read signed template file %s: %s", template, err)
		}
		sig2, content2 := signer.ExtractSignatureAndContent(bin2)
		hash2 := sha256.Sum256(content2)

		gologger.Info().Msgf("Updated Signature Details:")
		gologger.Info().Msgf("------------------------")
		gologger.Info().Msgf("Signature: %s", sig2)
		gologger.Info().Msgf("Content Hash (SHA256): %s\n", hex.EncodeToString(hash2[:]))
	}
	gologger.Info().Msgf("✓ Template signed & verified successfully")
}

func defaultExecutorOpts(templatePath string) protocols.ExecutorOptions {
	// use parsed options when initializing signer instead of default options
	options := types.DefaultOptions()
	templates.UseOptionsForSigner(options)
	catalog := disk.NewCatalog(filepath.Dir(templatePath))
	executerOpts := protocols.ExecutorOptions{
		Catalog:      catalog,
		Options:      options,
		TemplatePath: templatePath,
		Parser:       templates.NewParser(),
	}
	return executerOpts
}
