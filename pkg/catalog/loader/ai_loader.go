package loader

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/chroma/quick"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	"github.com/projectdiscovery/utils/errkit"
)

const (
	aiTemplateGeneratorAPIEndpoint = "https://api.projectdiscovery.io/v1/template/ai"
)

type AITemplateResponse struct {
	CanRun     bool   `json:"canRun"`
	Comment    string `json:"comment"`
	Completion string `json:"completion"`
	Message    string `json:"message"`
	Name       string `json:"name"`
	TemplateID string `json:"template_id"`
}

func getAIGeneratedTemplates(prompt string, options *types.Options) ([]string, error) {
	prompt = strings.TrimSpace(prompt)
	if len(prompt) < 5 {
		return nil, errkit.New("Prompt is too short. Please provide a more descriptive prompt").Build()
	}

	if len(prompt) > 3000 {
		return nil, errkit.New("Prompt is too long. Please limit to 3000 characters").Build()
	}

	template, templateID, err := generateAITemplate(prompt)
	if err != nil {
		return nil, errkit.New(fmt.Sprintf("Failed to generate template: %v", err)).Build()
	}

	pdcpTemplateDir := filepath.Join(config.DefaultConfig.GetTemplateDir(), "pdcp")
	if err := os.MkdirAll(pdcpTemplateDir, 0755); err != nil {
		return nil, errkit.New(fmt.Sprintf("Failed to create pdcp template directory: %v", err)).Build()
	}

	templateFile := filepath.Join(pdcpTemplateDir, templateID+".yaml")
	err = os.WriteFile(templateFile, []byte(template), 0644)
	if err != nil {
		return nil, errkit.New(fmt.Sprintf("Failed to generate template: %v", err)).Build()
	}

	options.Logger.Info().Msgf("Generated template available at: https://cloud.projectdiscovery.io/templates/%s", templateID)
	options.Logger.Info().Msgf("Generated template path: %s", templateFile)

	// Check if we should display the template
	// This happens when:
	// 1. No targets are provided (-target/-list)
	// 2. No stdin input is being used
	hasNoTargets := len(options.Targets) == 0 && options.TargetsFilePath == ""
	hasNoStdin := !options.Stdin

	if hasNoTargets && hasNoStdin {
		// Display the template content with syntax highlighting
		if !options.NoColor {
			var buf bytes.Buffer
			err = quick.Highlight(&buf, template, "yaml", "terminal16m", "monokai")
			if err == nil {
				template = buf.String()
			}
		}
		options.Logger.Debug().Msgf("\n%s", template)
		// FIXME:
		// we should not be exiting the program here
		// but we need to find a better way to handle this
		os.Exit(0)
	}

	return []string{templateFile}, nil
}

func generateAITemplate(prompt string) (string, string, error) {
	reqBody := map[string]string{
		"prompt": prompt,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", errkit.New(fmt.Sprintf("Failed to marshal request body: %v", err)).Build()
	}

	req, err := http.NewRequest(http.MethodPost, aiTemplateGeneratorAPIEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", "", errkit.New(fmt.Sprintf("Failed to create HTTP request: %v", err)).Build()
	}

	ph := pdcpauth.PDCPCredHandler{}
	creds, err := ph.GetCreds()
	if err != nil {
		return "", "", errkit.New(fmt.Sprintf("Failed to get PDCP credentials: %v", err)).Build()
	}

	if creds == nil {
		return "", "", errkit.New("PDCP API Key not configured, Create one for free at https://cloud.projectdiscovery.io/").Build()
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(pdcpauth.ApiKeyHeaderName, creds.APIKey)

	resp, err := retryablehttp.DefaultClient().Do(req)
	if err != nil {
		return "", "", errkit.New(fmt.Sprintf("Failed to send HTTP request: %v", err)).Build()
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", "", errkit.New("Invalid API Key or API Key not configured, Create one for free at https://cloud.projectdiscovery.io/").Build()
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", errkit.New(fmt.Sprintf("API returned status code %d: %s", resp.StatusCode, string(body))).Build()
	}

	var result AITemplateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", errkit.New(fmt.Sprintf("Failed to decode API response: %v", err)).Build()
	}

	if result.TemplateID == "" || result.Completion == "" {
		return "", "", errkit.New("Failed to generate template").Build()
	}

	return result.Completion, result.TemplateID, nil
}
