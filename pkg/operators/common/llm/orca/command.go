package orca

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/projectdiscovery/gologger"
)

// CredentialCommandOptions carries the terminal orcarouter commands. Both
// authentication methods are reachable from here: Login starts the PKCE connect
// flow, and every scan path accepts a pasted key through --llm-api-key or the
// environment.
type CredentialCommandOptions struct {
	// Login starts the OAuth 2.0 + PKCE connect flow.
	Login bool
	// Logout removes the stored credential.
	Logout bool
	// Status reports the stored credential without revealing it.
	Status bool
	// Models lists the models available to the current credential.
	Models bool
	// Flow selects auto, loopback or oob.
	Flow string
	// APIKey is an explicit key, so a non-interactive run can store one.
	APIKey string
	// Model optionally pins the model the Models command checks for
	// compatibility.
	Model string
	// AuthBaseURL and APIBaseURL are the explicit origin overrides.
	AuthBaseURL string
	// APIBaseURL is the inference origin override.
	APIBaseURL string

	// In and Out are the command's streams. Nil uses the process streams.
	In  io.Reader
	Out io.Writer
	// Timeout bounds the whole login.
	Timeout time.Duration
	// OpenBrowser overrides how the consent url is opened.
	OpenBrowser func(string) error
	// Store overrides the credential location.
	Store *CredentialStore
}

// RunCredentialCommand executes a terminal orcarouter command. It reports
// whether it handled anything, and the process exit code when it did.
func RunCredentialCommand(options CredentialCommandOptions) (bool, int) {
	if !options.Login && !options.Logout && !options.Status && !options.Models {
		return false, 0
	}

	out := options.Out
	if out == nil {
		out = os.Stdout
	}

	store := options.Store
	if store == nil {
		store = &CredentialStore{}
	}

	switch {
	case options.Logout:
		if err := store.Clear(); err != nil {
			fmt.Fprintf(out, "could not remove the stored orcarouter credential: %s\n", err)

			return true, 1
		}
		fmt.Fprintf(out, "Removed the stored OrcaRouter credential. A scan can still use --llm-api-key or %s.\n",
			strings.Join(APIKeyEnvNames, " / "))

		return true, 0
	case options.Status:
		return true, runStatus(out, store)
	case options.Models:
		return true, runModels(out, store, options)
	default:
		return true, runLogin(out, store, options)
	}
}

// runStatus reports the credential without printing it.
func runStatus(out io.Writer, store *CredentialStore) int {
	fmt.Fprintf(out, "OrcaRouter credential file: %s\n", store.path())

	credential, err := store.Load()
	if err != nil {
		fmt.Fprintf(out, "No usable credential: %s\n", err)
		fmt.Fprintf(out, "Authentication methods:\n")
		fmt.Fprintf(out, "  api key: --llm-api-key sk-orca-... or %s\n", strings.Join(APIKeyEnvNames, " / "))
		fmt.Fprintf(out, "  login:   nuclei -llm-login\n")

		return 0
	}

	fmt.Fprintf(out, "Key:        %s\n", credential.Masked())
	if credential.UserID != "" {
		fmt.Fprintf(out, "Account:    %s\n", credential.UserID)
	}
	if credential.Scope != "" {
		fmt.Fprintf(out, "Scope:      %s\n", credential.Scope)
	}
	fmt.Fprintf(out, "Generation: %d\n", credential.Generation)
	if !credential.IssuedAt.IsZero() {
		fmt.Fprintf(out, "Issued at:  %s\n", credential.IssuedAt.Format(time.RFC3339))
	}
	fmt.Fprintf(out, "Inference:  %s\n", EndpointsFromEnv().API)
	fmt.Fprintf(out, "Revoke at:  %s\n", ConsoleURL)

	return 0
}

// runModels lists the models the current credential can actually call.
func runModels(out io.Writer, store *CredentialStore, options CredentialCommandOptions) int {
	endpoints := resolveEndpoints(options.AuthBaseURL, options.APIBaseURL, os.Getenv(EnvSharedBase))
	if err := ValidateEndpoints(endpoints); err != nil {
		fmt.Fprintf(out, "%s\n", err)

		return 1
	}

	credential, err := credentialSource(options.APIKey, store).Credential()
	if err != nil {
		fmt.Fprintf(out, "%s\n", err)

		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	catalog := DiscoverModels(ctx, endpoints, credential.Key)
	filter := ChatFilter()

	models := catalog.Filtered(filter)
	if catalog.Live {
		fmt.Fprintf(out, "Models for text chat from %s%s (live catalog, %d of %d entries compatible):\n",
			endpoints.API, ModelsPath, len(models), len(catalog.Models))
	} else {
		fmt.Fprintf(out, "live catalog unavailable (%s); showing the verified fallback list.\n", catalog.Error)
	}

	for _, model := range models {
		metadata := make([]string, 0, 3)
		if model.ContextLength > 0 {
			metadata = append(metadata, fmt.Sprintf("ctx %d", model.ContextLength))
		}
		if len(model.InputModalities) > 0 {
			metadata = append(metadata, "input "+joinModalities(model.InputModalities))
		}
		if model.Reasoning {
			efforts := ""
			if len(model.ReasoningEfforts) > 0 {
				efforts = " (" + strings.Join(model.ReasoningEfforts, "/") + ")"
			}
			metadata = append(metadata, "reasoning"+efforts)
		}
		if model.Verified {
			metadata = append(metadata, "verified fallback")
		}

		line := "  " + model.ID
		if len(metadata) > 0 {
			line += "  [" + strings.Join(metadata, ", ") + "]"
		}
		fmt.Fprintln(out, line)
	}

	if len(models) == 0 {
		fmt.Fprintln(out, "  (no compatible model)")
	}

	return 0
}

func joinModalities(modalities []InputModality) string {
	values := make([]string, 0, len(modalities))
	for _, modality := range modalities {
		values = append(values, string(modality))
	}

	return strings.Join(values, "+")
}

// runLogin runs the PKCE connect flow and stores the issued key.
func runLogin(out io.Writer, store *CredentialStore, options CredentialCommandOptions) int {
	endpoints := resolveEndpoints(options.AuthBaseURL, options.APIBaseURL, os.Getenv(EnvSharedBase))
	if err := ValidateEndpoints(endpoints); err != nil {
		fmt.Fprintf(out, "%s\n", err)

		return 1
	}

	flow := Flow(strings.ToLower(strings.TrimSpace(options.Flow)))
	switch flow {
	case "", "auto":
		flow = ""
	case FlowLoopback, FlowOutOfBand:
	default:
		fmt.Fprintf(out, "unknown login flow %q: use auto, loopback or oob\n", options.Flow)

		return 1
	}

	// A stored credential is reused rather than replaced. Re-authorizing on
	// every launch would burn the 10-keys-per-user-per-24-hours budget.
	if !options.Login && options.APIKey == "" {
		if credential, err := store.Load(); err == nil {
			fmt.Fprintf(out, "Already connected as %s (%s). Use --llm-logout first to replace it.\n",
				credential.Masked(), credential.UserID)

			return 0
		}
	}

	fmt.Fprintf(out, "Connecting to OrcaRouter at %s\n", endpoints.Auth)
	fmt.Fprintf(out, "Authentication is separate from inference: keys are issued by %s and used against %s.\n",
		endpoints.Auth, endpoints.API)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	credential, err := Login(ctx, store, LoginOptions{
		Endpoints:  endpoints,
		AppName:    AppName,
		Flow:       flow,
		PromptCode: promptCode(out, options.In),
		OpenBrowser: func(url string) error {
			if options.OpenBrowser != nil {
				return options.OpenBrowser(url)
			}

			return openBrowser(url)
		},
		OnAuthorizeURL: func(url string) {
			fmt.Fprintf(out, "\nOpen this url to authorize:\n  %s\n\n", url)
		},
		Timeout: options.Timeout,
	})
	if err != nil {
		fmt.Fprintf(out, "OrcaRouter login failed: %s\n", DescribePKCEError(err))

		return 1
	}

	fmt.Fprintf(out, "Connected. Stored %s for account %s (scope %q, generation %d).\n",
		credential.Masked(), credential.UserID, credential.Scope, credential.Generation)
	fmt.Fprintf(out, "Scans will reuse this key until it is revoked at %s.\n", ConsoleURL)

	return 0
}

// credentialSource builds the credential seam for a terminal command: an
// explicit key or the environment wins over the stored credential, so a user can
// point one command at another account without disturbing what is stored.
func credentialSource(explicitKey string, store *CredentialStore) CredentialSource {
	return DefaultCredentialSource(firstNonEmpty(explicitKey, APIKeyFromEnv()), store)
}

// promptCode reads an out-of-band code from the terminal. It is nil-safe: a
// caller with no terminal gets a typed error instead of a hang.
//
// The code is read by line rather than by character device, so a code piped in
// from another process still works and the prompt does not corrupt a log.
func promptCode(out io.Writer, in io.Reader) func(string) (string, error) {
	if in == nil {
		in = os.Stdin
	}

	return func(_ string) (string, error) {
		fmt.Fprintln(out, "Paste the code shown on the OrcaRouter consent screen:")

		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}

		return strings.TrimSpace(line), nil
	}
}

// openBrowser opens a url with the platform handler. Failure is not fatal: the
// url has already been printed for the user to open by hand.
func openBrowser(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("open", url)
	case "windows":
		command = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		command = exec.Command("xdg-open", url)
	}

	return command.Start()
}

// LogCredentialNotice writes the one-line notice a scan prints when it is using
// OrcaRouter, so the credential source is visible without leaking the key.
func LogCredentialNotice(logger *gologger.Logger, source Source, masked string, endpoints Endpoints) {
	if logger == nil {
		return
	}

	logger.Info().Msgf("OrcaRouter: using %s credential %s against %s (auth %s)\n",
		source, masked, endpoints.API, endpoints.Auth)
}

// SortedModelIDs is a helper for tests and diagnostics.
func SortedModelIDs(models []Model) []string {
	ids := make([]string, 0, len(models))
	for _, model := range models {
		ids = append(ids, model.ID)
	}
	sort.Strings(ids)

	return ids
}
