package loader

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"

	"github.com/alecthomas/chroma/quick"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	pdcpauth "github.com/projectdiscovery/utils/auth/pdcp"
	errorutil "github.com/projectdiscovery/utils/errors"
)

const (
	aiTemplateAPIEndpoint = "https://api.projectdiscovery.io/v1/template/ai"
)

type AITemplateResponse struct {
	CanRun     bool   `json:"canRun"`
	Comment    string `json:"comment"`
	Completion string `json:"completion"`
	Message    string `json:"message"`
	Name       string `json:"name"`
	TemplateID string `json:"template_id"`
}

func getAIGeneratedTemplates(prompt string, options *types.Options) ([]string, string, error) {
	if prompt == "" {
		return nil, "", nil
	}

	template, templateID, err := generateAITemplate(prompt)
	if err != nil {
		gologger.Info().Msg("Failed to generate template")
		os.Exit(1)
	}

	tempDir, err := os.MkdirTemp("", "nuclei-ai-templates-*")
	if err != nil {
		gologger.Info().Msg("Failed to generate template")
		os.Exit(1)
	}

	tempFile := filepath.Join(tempDir, templateID+".yaml")
	err = os.WriteFile(tempFile, []byte(template), 0644)
	if err != nil {
		os.RemoveAll(tempDir) 
		gologger.Info().Msg("Failed to generate template")
		os.Exit(1)
	}

	// Check if we should display the template
	// This happens when:
	// 1. No targets are provided (-target/-list)
	// 2. No stdin input is being used
	hasNoTargets := len(options.Targets) == 0 && options.TargetsFilePath == ""
	hasNoStdin := !options.Stdin && options.DisableStdin
	
	if hasNoTargets && hasNoStdin {
		// Display the template content with syntax highlighting
		if !options.NoColor {
			var buf bytes.Buffer
			err = quick.Highlight(&buf, template, "yaml", "terminal16m", "monokai")
			if err == nil {
				template = buf.String()
			}
		}
		gologger.Silent().Msgf("Template: %s\n\n%s", tempFile, template)
		gologger.Info().Msgf("Generated template available at: https://cloud.projectdiscovery.io/templates/%s", templateID)
		os.Exit(0)
	}

	gologger.Info().Msgf("Generated template path: %s", tempFile)
	return []string{tempFile}, tempDir, nil
}

func generateAITemplate(prompt string) (string, string, error) {
	reqBody := map[string]string{
		"prompt": prompt,
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", "", errorutil.New("Failed to generate template")
	}

	req, err := http.NewRequest(http.MethodPost, aiTemplateAPIEndpoint, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", "", errorutil.New("Failed to generate template")
	}

	ph := pdcpauth.PDCPCredHandler{}
	creds, err := ph.GetCreds()
	if creds == nil {
		gologger.Info().Msg("PDCP API Key not configured, Create one for free at https://cloud.projectdiscovery.io/")
		os.Exit(1)
	}
	if err != nil {
		return "", "", errorutil.New("Failed to get PDCP credentials")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(pdcpauth.ApiKeyHeaderName, creds.APIKey)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", errorutil.New("Failed to generate template")
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		gologger.Info().Msg("Invalid API Key or API Key not configured, Create one for free at https://cloud.projectdiscovery.io/")
		os.Exit(1)
	}

	if resp.StatusCode != http.StatusOK {
		return "", "", errorutil.New("Failed to generate template")
	}

	var result AITemplateResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", errorutil.New("Failed to generate template")
	}

	if result.TemplateID == "" || result.Completion == "" {
		return "", "", errorutil.New("Failed to generate template")
	}

	gologger.Info().Msgf("Generated template available at: https://cloud.projectdiscovery.io/templates/%s", result.TemplateID)

	return result.Completion, result.TemplateID, nil
} 