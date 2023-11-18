// pdcp contains projectdiscovery cloud platform related features
// like result upload , dashboard etc.
package pdcp

import (
	"fmt"
	"os"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/utils/env"
	"golang.org/x/term"
)

var (
	DashBoardURL     = "https://cloud.projectdiscovery.io"
	DefaultApiServer = "https://api.projectdiscovery.io"
)

// CheckNValidateCredentials checks if credentials exist on filesystem
// if not waits for user to enter credentials and validates them
// and saves them to filesystem
// when validate is true any existing credentials are validated
// Note: this is meant to be used in cli only (interactive mode)
func CheckNValidateCredentials(toolName string) {
	h := &PDCPCredHandler{}
	creds, err := h.GetCreds()
	if err == nil {
		// validate by fetching user profile
		gotCreds, err := h.ValidateAPIKey(creds.APIKey, creds.Server, config.BinaryName)
		if err == nil {
			gologger.Info().Msgf("You are logged in as (@%v)", gotCreds.Username)
			os.Exit(0)
		}
		gologger.Error().Msgf("Invalid API key found in file, please recheck or recreate your API key and retry.")
	}
	if err != nil && err != ErrNoCreds {
		// this is unexpected error log it
		gologger.Error().Msgf("Could not read credentials from file: %s\n", err)
	}

	// if we are here, we need to get credentials from user
	gologger.Info().Msgf("Get your free api key by signing up at %v", DashBoardURL)
	fmt.Printf("[*] Enter PDCP API Key (exit to abort): ")
	bin, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		gologger.Fatal().Msgf("Could not read input from terminal: %s\n", err)
	}
	apiKey := string(bin)
	if strings.EqualFold(apiKey, "exit") {
		os.Exit(0)
	}
	fmt.Println()
	// if env variable is set use that for validating api key
	apiServer := env.GetEnvOrDefault(apiServerEnv, DefaultApiServer)
	// validate by fetching user profile
	validatedCreds, err := h.ValidateAPIKey(apiKey, apiServer, toolName)
	if err == nil {
		gologger.Info().Msgf("Successfully logged in as (@%v)", validatedCreds.Username)
		if saveErr := h.SaveCreds(validatedCreds); saveErr != nil {
			gologger.Warning().Msgf("Could not save credentials to file: %s\n", saveErr)
		}
		os.Exit(0)
	}
	gologger.Error().Msgf("Invalid API key '%v' got error: %v", maskKey(apiKey), err)
	gologger.Fatal().Msgf("please recheck or recreate your API key and retry")
}

func maskKey(key string) string {
	if len(key) < 6 {
		// this is invalid key
		return key
	}
	return fmt.Sprintf("%v%v", key[:3], strings.Repeat("*", len(key)-3))
}
