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
// It is safe to call multiple times; errors from os.Remove are ignored.
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
//     Only non-empty static/dynamic sections are written to avoid producing
//     an authx file that pkg/authprovider/file.go would reject with ErrNoSecrets.
//
// The function returns a ProfilePreprocessResult. The caller should use
// CleanedConfigPath with goflags.MergeConfigFile and call Cleanup() when done.
func PreprocessProfileFile(filePath string) (*ProfilePreprocessResult, error) {
	result := &ProfilePreprocessResult{}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Parse YAML into a map. An empty file will produce a nil map, which is
	// safe to pass to hasSpecialKeys (nil map range is a no-op in Go).
	var rawConfig map[string]interface{}
	if err := yaml.Unmarshal(data, &rawConfig); err != nil {
		return nil, err
	}

	// If there are no special keys to process, return the original file path
	// with no temp files created — fast path for normal config files.
	if !hasSpecialKeys(rawConfig) {
		result.CleanedConfigPath = filePath
		return result, nil
	}

	// --- Feature 1: Remove extra metadata fields ---
	// Keys like id, name, purpose, description are stripped so goflags
	// does not error on unrecognised flag names.
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

	// Serialize the cleaned config (extra fields removed, inline values
	// replaced with temp file paths) to a new temporary YAML file so that
	// goflags.MergeConfigFile only sees standard flag names.
	cleanedData, err := yaml.Marshal(rawConfig)
	if err != nil {
		result.Cleanup()
		return nil, err
	}

	// os.CreateTemp creates the file with 0600 permissions, ensuring that
	// the cleaned config (which may reference secrets paths) is not world-readable.
	tmpFile, err := os.CreateTemp("", "nuclei-profile-*.yaml")
	if err != nil {
		result.Cleanup()
		return nil, err
	}
	// Register path in TempFiles and CleanedConfigPath BEFORE writing so that
	// Cleanup() always removes this file even if the subsequent write fails.
	result.CleanedConfigPath = tmpFile.Name()
	result.TempFiles = append(result.TempFiles, tmpFile.Name())

	if _, err := tmpFile.Write(cleanedData); err != nil {
		_ = tmpFile.Close()
		result.Cleanup()
		return nil, err
	}
	_ = tmpFile.Close()

	return result, nil
}

// hasSpecialKeys reports whether rawConfig contains any key that requires
// preprocessing: extra metadata fields, an inline secrets block, or an inline
// targets list (multiline "list" value).
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

// isNonEmptySlice returns true if v is a []interface{} with at least one element.
// It is used to guard against YAML null values (nil) and empty lists ([]interface{}{})
// when checking inline secrets sections.
//
// This guard is required because pkg/authprovider/file.go (NewFileAuthProvider)
// returns ErrNoSecrets when both store.Secrets and store.Dynamic are empty.
// Writing a temp authx file from static: null / static: [] / dynamic: null /
// dynamic: [] would create a file that passes parsing but fails that check,
// turning a harmless no-op profile entry into a startup error.
func isNonEmptySlice(v interface{}) bool {
	if v == nil {
		return false
	}
	slice, ok := v.([]interface{})
	return ok && len(slice) > 0
}

// handleInlineTargets checks if the "list" key contains a multiline string
// (inline target list). If so, it writes the targets to a temp file and
// replaces the "list" value with the temp file path, so goflags can treat
// it as a normal -list file path.
func handleInlineTargets(rawConfig map[string]interface{}, result *ProfilePreprocessResult) error {
	listVal, ok := rawConfig["list"]
	if !ok {
		return nil
	}

	strVal, isStr := listVal.(string)
	if !isStr {
		return nil
	}

	// Only treat as inline targets if the value contains newlines.
	// A plain file path (e.g. "/path/to/targets.txt") must not be treated
	// as an inline list even if it somehow appears as a string value.
	if !strings.Contains(strVal, "\n") {
		return nil
	}

	// Parse targets: split by newlines, trim whitespace, skip empty lines.
	var targets []string
	for _, line := range strings.Split(strVal, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			targets = append(targets, line)
		}
	}

	// Whitespace-only block scalar → remove the key entirely; no temp file needed.
	if len(targets) == 0 {
		delete(rawConfig, "list")
		return nil
	}

	// os.CreateTemp creates the file with 0600 permissions by default.
	tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return err
	}
	// Register path BEFORE writing so Cleanup() handles removal on write failure.
	result.InlineTargetsFile = tmpFile.Name()
	result.TempFiles = append(result.TempFiles, tmpFile.Name())

	content := strings.Join(targets, "\n") + "\n"
	if _, err := tmpFile.WriteString(content); err != nil {
		_ = tmpFile.Close()
		// Do NOT call os.Remove here — result.TempFiles already holds the path
		// and the caller's result.Cleanup() will handle removal.
		return err
	}
	_ = tmpFile.Close()

	// Replace the multiline string with the temp file path so goflags
	// can parse it as a normal file path for the -list flag.
	rawConfig["list"] = tmpFile.Name()

	return nil
}

// handleInlineSecrets checks if a "secrets" key exists in the config.
// If so, it extracts the secrets data, writes it to a temporary YAML file
// in the authx format (with "static" and "dynamic" top-level keys), and
// adds the temp file path to the "secret-file" list in the cleaned config.
//
// The "secrets" key is always removed from rawConfig because goflags must
// never see it; the information is forwarded via "secret-file" instead.
//
// Only non-nil, non-empty static and dynamic sections are included in the
// written authx file. If both sections are empty or null after filtering,
// no temp file is created. This prevents pkg/authprovider/file.go from
// returning ErrNoSecrets on startup due to a vacuous secrets: block.
func handleInlineSecrets(rawConfig map[string]interface{}, result *ProfilePreprocessResult) error {
	secretsVal, ok := rawConfig["secrets"]
	if !ok {
		return nil
	}

	// Remove the "secrets" key unconditionally — goflags must never see it.
	delete(rawConfig, "secrets")

	secretsMap, isMap := secretsVal.(map[string]interface{})
	if !isMap {
		// Value is present but not a map (e.g. a plain string). Skip silently
		// rather than erroring, to stay backwards-compatible.
		return nil
	}

	// Build the authx-compatible secrets file content.
	// The authx provider expects top-level "static" and "dynamic" keys.
	//
	// IMPORTANT: We only add a section when its value is a non-nil, non-empty
	// slice. YAML null (nil interface{}) and empty lists ([]interface{}{}) are
	// filtered out here. Writing such values would produce an authx file where
	// both store.Secrets and store.Dynamic are empty, causing NewFileAuthProvider
	// to return ErrNoSecrets and aborting the scan at startup.
	authxData := make(map[string]interface{})

	if staticVal, ok := secretsMap["static"]; ok && isNonEmptySlice(staticVal) {
		authxData["static"] = staticVal
	}
	if dynamicVal, ok := secretsMap["dynamic"]; ok && isNonEmptySlice(dynamicVal) {
		authxData["dynamic"] = dynamicVal
	}

	// No usable secrets sections — nothing to write.
	if len(authxData) == 0 {
		return nil
	}

	secretsYAML, err := yaml.Marshal(authxData)
	if err != nil {
		return err
	}

	// os.CreateTemp creates the file with 0600 permissions by default,
	// protecting sensitive auth data from other users on the system.
	tmpFile, err := os.CreateTemp("", "nuclei-secrets-*.yaml")
	if err != nil {
		return err
	}
	// Register path BEFORE writing so Cleanup() handles removal on write failure.
	result.InlineSecretsFile = tmpFile.Name()
	result.TempFiles = append(result.TempFiles, tmpFile.Name())

	if _, err := tmpFile.Write(secretsYAML); err != nil {
		_ = tmpFile.Close()
		// Do NOT call os.Remove here — result.TempFiles already holds the path
		// and the caller's result.Cleanup() will handle removal.
		return err
	}
	_ = tmpFile.Close()

	// Add the temp secrets file to the "secret-file" list in the config.
	// We always write a YAML sequence ([]interface{}) so that goflags'
	// CommaSeparatedStringSliceOptions can parse it reliably, regardless of
	// spacing or quoting that might exist in an existing "secret-file" value.
	secretFilePath := filepath.ToSlash(tmpFile.Name())
	if existing, ok := rawConfig["secret-file"]; ok {
		switch v := existing.(type) {
		case string:
			if v != "" {
				rawConfig["secret-file"] = []interface{}{v, secretFilePath}
			} else {
				rawConfig["secret-file"] = []interface{}{secretFilePath}
			}
		case []interface{}:
			rawConfig["secret-file"] = append(v, secretFilePath)
		default:
			rawConfig["secret-file"] = []interface{}{secretFilePath}
		}
	} else {
		rawConfig["secret-file"] = []interface{}{secretFilePath}
	}

	return nil
}
