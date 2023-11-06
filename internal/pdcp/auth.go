// pdcp contains projectdiscovery cloud platform related features
// like result upload , dashboard etc.
package pdcp

import (
	"fmt"
	"os"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/utils/env"
	"golang.org/x/term"
)

const (
	LoginURL         = "https://cloud.projectdiscovery.io"
	DefaultApiServer = "https://api.dev.projectdiscovery.io"
)

// CheckCredentials checks if credentials exist on filesystem
// if not waits for user to enter credentials and validates them
// and saves them to filesystem
// when validate is true any existing credentials are validated
// Note: this is meant to be used in cli only (interactive mode)
func CheckCredentials(toolName string, validate bool) {
	h := &PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err == nil {
		if !validate {
			return
		}
		// validate by fetching user profile
		_, err := h.ValidateAPIKey(creds.APIKey, creds.Server, config.BinaryName)
		if err == nil {
			return
		}
		gologger.Error().Msgf("Invalid API key found in file, please recheck or recreate your API key and retry.")
	}

	// if we are here, we need to get credentials from user
	gologger.Info().Msgf("Get your free api key by signing up at %v", LoginURL)
	fmt.Printf("[*] Enter PDCP API Key (exit to abort): ")
	bin, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		gologger.Fatal().Msgf("Could not read input from terminal: %s\n", err)
	}
	apiKey := string(bin)
	if apiKey == "exit" {
		os.Exit(0)
	}
	// if env variable is set use that for validating api key
	apiServer := env.GetEnvOrDefault(apiServerEnv, DefaultApiServer)
	// validate by fetching user profile
	validatedCreds, err := h.ValidateAPIKey(apiKey, apiServer, toolName)
	if err == nil {
		gologger.Info().Msgf("Successfully logged in as (@%v)", validatedCreds.Username)
		if saveErr := h.SaveCreds(validatedCreds); saveErr != nil {
			gologger.Warning().Msgf("Could not save credentials to file: %s\n", saveErr)
		}
		return
	}
	gologger.Fatal().Msgf("Invalid API key, please recheck or recreate your API key and retry")
}
