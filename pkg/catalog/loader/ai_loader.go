package loader

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/chroma/quick"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/retryablehttp-go"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	errorutil "github.com/projectdiscovery/utils/errors"
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
		return nil, errorutil.New("Prompt is too short. Please provide a more descriptive prompt")
	}

	if len(prompt) > 3000 {
		return nil, errorutil.New("Prompt is too long. Please limit to 3000 characters")
	}

	template, templateID, err := generateAITemplate(prompt)
	if err != nil {
		return nil, errorutil.New("Failed to generate template: %v", err)
	}

	pdcpTemplateDir := filepath.Join(config.DefaultConfig.GetTemplateDir(), "pdcp")
	if err := os.MkdirAll(pdcpTemplateDir, 0755); err != nil {
		return nil, errorutil.New("Failed to create pdcp template directory: %v", err)
	}

	templateFile := filepath.Join(pdcpTemplateDir, templateID+".yaml")
	err = os.WriteFile(templateFile, []byte(template), 0644)
	if err != nil {
		return nil, errorutil.New("Failed to generate template: %v", err)
	}

	gologger.Info().Msgf("Generated template available at: https://cloud.projectdiscovery.io/templates/%s", templateID)
	gologger.Info().Msgf("Generated template path: %s", templateFile)

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
		gologger.Silent().Msgf("\n%s", template)
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
		return "", "", errorutil.New("Failed to marshal request body: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, aiTemplateGeneratorAPIEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", "", errorutil.New("Failed to create HTTP request: %v", err)
	}

	ph := pdcpauth.PDCPCredHandler{}
	creds, err := ph.GetCreds()
	if err != nil {
		return "", "", errorutil.New("Failed to get PDCP credentials: %v", err)
	}

	if creds == nil {
		return "", "", errorutil.New("PDCP API Key not configured, Create one for free at https://cloud.projectdiscovery.io/")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(pdcpauth.ApiKeyHeaderName, creds.APIKey)

	resp, err := retryablehttp.DefaultClient().Do(req)
	if err != nil {
		return "", "", errorutil.New("Failed to send HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", "", errorutil.New("Invalid API Key or API Key not configured, Create one for free at https://cloud.projectdiscovery.io/")
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", "", errorutil.New("API returned status code %d: %s", resp.StatusCode, string(body))
	}

	var result AITemplateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", errorutil.New("Failed to decode API response: %v", err)
	}

	if result.TemplateID == "" || result.Completion == "" {
		return "", "", errorutil.New("Failed to generate template")
	}

	return result.Completion, result.TemplateID, nil
}
