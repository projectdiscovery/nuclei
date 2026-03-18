package authx

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// ExtractSecretsFromProfile reads a YAML profile/config file and extracts
// the secrets section, writing it to a temporary file that can be used
// as a secrets file for nuclei authenticated scans.
// This allows embedding secrets directly in template profiles instead of
// passing them via a separate file.
func ExtractSecretsFromProfile(profilePath string) (string, error) {
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return "", fmt.Errorf("could not read profile: %w", err)
	}

	// Parse the YAML into a generic map to extract the secrets section
	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return "", fmt.Errorf("could not parse profile yaml: %w", err)
	}

	secretsData, ok := raw["secrets"]
	if !ok {
		// No secrets section in the profile
		return "", nil
	}

	// The secrets section in a profile may contain 'static' and/or 'dynamic' keys.
	// The Authx format expects these at the top level (not nested under 'secrets'),
	// so we extract and write them directly as the top-level keys.
	secretsMap, ok := secretsData.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("secrets section must be a mapping, got %T", secretsData)
	}

	// Marshal the inner content (static/dynamic) directly as top-level YAML
	secretsYAML, err := yaml.Marshal(secretsMap)
	if err != nil {
		return "", fmt.Errorf("could not marshal secrets section: %w", err)
	}

	// Write to a temporary file
	tmpFile, err := os.CreateTemp("", "nuclei-secrets-*.yaml")
	if err != nil {
		return "", fmt.Errorf("could not create temp secrets file: %w", err)
	}
	defer tmpFile.Close()

	if _, err := tmpFile.Write(secretsYAML); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("could not write temp secrets file: %w", err)
	}

	return tmpFile.Name(), nil
}
