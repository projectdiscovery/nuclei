package types

import (
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// profileExtraFields are metadata fields that are allowed in template profiles
// and config files but are not recognized goflags options. These fields are
// silently ignored during preprocessing so that users can annotate profiles
// with human-readable metadata without triggering parse errors.
var profileExtraFields = map[string]bool{
	"id":          true,
	"name":        true,
	"purpose":     true,
	"description": true,
}

// ProfilePreprocessResult holds the results of preprocessing a template profile
// or config file. It contains the path to the cleaned config file suitable for
// goflags.MergeConfigFile and any temporary files that were created during
// preprocessing (for inline targets and inline secrets).
type ProfilePreprocessResult struct {
	// CleanedConfigPath is the path to the cleaned YAML config file
	// that can be passed to goflags.MergeConfigFile. Extra fields are
	// removed and inline targets/secrets are replaced with file references.
	CleanedConfigPath string

	// TempFiles holds paths to all temporary files created during
	// preprocessing. The caller is responsible for cleaning these up
	// when they are no longer needed (typically at program exit).
	TempFiles []string

	// InlineSecretsFile is the path to the temporary secrets file
	// generated from inline secrets data, or empty if no inline
	// secrets were present.
	InlineSecretsFile string

	// InlineTargetsFile is the path to the temporary targets file
	// generated from inline target list data, or empty if no inline
	// targets were present.
	InlineTargetsFile string
}

// Cleanup removes all temporary files created during preprocessing.
func (p *ProfilePreprocessResult) Cleanup() {
	for _, f := range p.TempFiles {
		_ = os.Remove(f)
	}
}

// PreprocessProfileFile reads a template profile or config YAML file and
// preprocesses it to support three features from issue #5567:
//
//  1. Extra fields (id, name, purpose, description) are silently removed
//     so that goflags.MergeConfigFile does not error on unknown keys.
//
//  2. Inline targets: if the "list" key contains a multiline string (YAML
//     block scalar) instead of a file path, the targets are written to a
//     temporary file and the "list" value is replaced with the temp file path.
//
//  3. Inline secrets: if a "secrets" key exists, its content (static/dynamic)
//     is serialized as a proper authx YAML secrets file in a temp file, and a
//     "secret-file" entry is added (or appended) to the cleaned config.
//
// The function returns a ProfilePreprocessResult. The caller should use
// CleanedConfigPath with goflags.MergeConfigFile and call Cleanup() when done.
func PreprocessProfileFile(filePath string) (*ProfilePreprocessResult, error) {
	result := &ProfilePreprocessResult{}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Parse YAML into an ordered map to preserve key order
	var rawConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return nil, err
	}

	// If there are no special keys to process, return the original file path
	if !hasSpecialKeys(rawConfig) {
		result.CleanedConfigPath = filePath
		return result, nil
	}

	// --- Feature 1: Remove extra metadata fields ---
	for field := range profileExtraFields {
		delete(rawConfig, field)
	}

	// --- Feature 2: Handle inline targets (list key with multiline content) ---
	if err := handleInlineTargets(rawConfig, result); err != nil {
		result.Cleanup()
		return nil, err
	}

	// --- Feature 3: Handle inline secrets ---
	if err := handleInlineSecrets(rawConfig, result); err != nil {
		result.Cleanup()
		return nil, err
	}

	// Write the cleaned config to a temporary file
	cleanedData, err := yaml.Marshal(rawConfig)
	if err != nil {
		result.Cleanup()
		return nil, err
	}

	tmpFile, err := os.CreateTemp("", "nuclei-profile-*.yaml")
	if err != nil {
		result.Cleanup()
		return nil, err
	}

	if _, err := tmpFile.Write(cleanedData); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		result.Cleanup()
		return nil, err
	}
	_ = tmpFile.Close()

	result.CleanedConfigPath = tmpFile.Name()
	result.TempFiles = append(result.TempFiles, tmpFile.Name())

	return result, nil
}

// hasSpecialKeys checks whether the raw config contains any keys that
// require preprocessing (extra metadata fields, inline targets, or inline secrets).
func hasSpecialKeys(rawConfig map[string]interface{}) bool {
	for field := range profileExtraFields {
		if _, ok := rawConfig[field]; ok {
			return true
		}
	}
	if _, ok := rawConfig["secrets"]; ok {
		return true
	}
	if listVal, ok := rawConfig["list"]; ok {
		if strVal, isStr := listVal.(string); isStr {
			if strings.Contains(strVal, "\n") {
				return true
			}
		}
	}
	return false
}

// handleInlineTargets checks if the "list" key contains a multiline string
// (inline target list). If so, it writes the targets to a temp file and
// replaces the "list" value with the temp file path.
func handleInlineTargets(rawConfig map[string]interface{}, result *ProfilePreprocessResult) error {
	listVal, ok := rawConfig["list"]
	if !ok {
		return nil
	}

	strVal, isStr := listVal.(string)
	if !isStr {
		return nil
	}

	// Only treat as inline targets if the value contains newlines
	// (i.e., it's a YAML block scalar with multiple targets, not a file path)
	if !strings.Contains(strVal, "\n") {
		return nil
	}

	// Parse targets from the multiline string: split by newlines, trim whitespace,
	// and skip empty lines
	var targets []string
	for _, line := range strings.Split(strVal, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			targets = append(targets, line)
		}
	}

	if len(targets) == 0 {
		delete(rawConfig, "list")
		return nil
	}

	// Write targets to a temporary file (one per line)
	tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return err
	}

	content := strings.Join(targets, "\n") + "\n"
	if _, err := tmpFile.WriteString(content); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return err
	}
	_ = tmpFile.Close()

	result.InlineTargetsFile = tmpFile.Name()
	result.TempFiles = append(result.TempFiles, tmpFile.Name())

	// Replace the multiline string with the temp file path so goflags
	// can parse it as a normal file path for the -list flag
	rawConfig["list"] = tmpFile.Name()

	return nil
}

// handleInlineSecrets checks if a "secrets" key exists in the config.
// If so, it extracts the secrets data, writes it to a temporary YAML file
// in the authx format (with "static" and "dynamic" top-level keys), and
// adds the temp file path to the "secret-file" list in the cleaned config.
func handleInlineSecrets(rawConfig map[string]interface{}, result *ProfilePreprocessResult) error {
	secretsVal, ok := rawConfig["secrets"]
	if !ok {
		return nil
	}

	// Remove the "secrets" key from the config since goflags doesn't know about it
	delete(rawConfig, "secrets")

	secretsMap, isMap := secretsVal.(map[string]interface{})
	if !isMap {
		// If secrets is not a map, skip silently
		return nil
	}

	// Build the authx-compatible secrets file content.
	// The authx format expects top-level "static" and "dynamic" keys.
	authxData := make(map[string]interface{})
	if staticVal, ok := secretsMap["static"]; ok {
		authxData["static"] = staticVal
	}
	if dynamicVal, ok := secretsMap["dynamic"]; ok {
		authxData["dynamic"] = dynamicVal
	}

	if len(authxData) == 0 {
		return nil
	}

	// Serialize to YAML
	secretsYAML, err := yaml.Marshal(authxData)
	if err != nil {
		return err
	}

	// Write to a temporary file
	tmpFile, err := os.CreateTemp("", "nuclei-secrets-*.yaml")
	if err != nil {
		return err
	}

	if _, err := tmpFile.Write(secretsYAML); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return err
	}
	_ = tmpFile.Close()

	result.InlineSecretsFile = tmpFile.Name()
	result.TempFiles = append(result.TempFiles, tmpFile.Name())

	// Add the temp secrets file to the "secret-file" list in the config.
	// The "secret-file" flag accepts a comma-separated list of file paths.
	secretFilePath := filepath.ToSlash(tmpFile.Name())
	if existing, ok := rawConfig["secret-file"]; ok {
		switch v := existing.(type) {
		case string:
			if v != "" {
				rawConfig["secret-file"] = v + "," + secretFilePath
			} else {
				rawConfig["secret-file"] = secretFilePath
			}
		case []interface{}:
			rawConfig["secret-file"] = append(v, secretFilePath)
		default:
			rawConfig["secret-file"] = secretFilePath
		}
	} else {
		rawConfig["secret-file"] = secretFilePath
	}

	return nil
}
