package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
)

// internalTempFiles tracks temporary files created during config processing
// so they can be cleaned up after the scan completes.
var internalTempFiles []string

// cleanupInternalTempFiles removes any temporary files created during config processing.
func cleanupInternalTempFiles() {
	for _, f := range internalTempFiles {
		_ = os.Remove(f)
	}
}

// processConfigExtras handles special YAML keys in config/profile files that require
// custom processing beyond what goflags.MergeConfigFile provides:
//
//   - list: supports inline targets as a block scalar (multi-line string) or a YAML
//     list of strings, in addition to the existing file-path string form.
//
//   - secrets: allows embedding auth config inline rather than pointing to a separate
//     file. The section is written to a temporary file and appended to SecretsFile so
//     the existing auth-provider machinery picks it up transparently.
//
// Unknown YAML keys (e.g. name, purpose, id, description) are silently ignored by
// goflags.MergeConfigFile; this function does not change that behaviour.
func processConfigExtras(filePath string, opts *types.Options) error {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	var raw map[string]interface{}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		// Not a valid YAML file - goflags already handles the error; nothing to do.
		return nil
	}

	if err := applyInlineList(raw, opts); err != nil {
		return err
	}

	if err := applyInlineSecrets(raw, opts); err != nil {
		return err
	}

	return nil
}

// applyInlineList handles the "list" key when it contains inline targets instead of
// a file path. Supported forms:
//
//	list: |
//	  target1.example.com
//	  target2.example.com
//
//	list:
//	  - target1.example.com
//	  - target2.example.com
//
// If the current TargetsFilePath already points to an existing file (set via the
// -l CLI flag), it is left unchanged so CLI flags keep their higher priority.
func applyInlineList(raw map[string]interface{}, opts *types.Options) error {
	listVal, ok := raw["list"]
	if !ok {
		return nil
	}

	var targets []string

	switch v := listVal.(type) {
	case string:
		// A block scalar ("|") produces a string with embedded newlines.
		// A plain single-line string is an existing file path; let goflags handle it.
		lines := strings.Split(strings.TrimSpace(v), "\n")
		if len(lines) <= 1 {
			// Single value: treat as a file path (goflags already handled it).
			return nil
		}
		for _, line := range lines {
			if t := strings.TrimSpace(line); t != "" {
				targets = append(targets, t)
			}
		}

	case []interface{}:
		// YAML sequence: each element is an inline target.
		for _, item := range v {
			if s, ok := item.(string); ok {
				if t := strings.TrimSpace(s); t != "" {
					targets = append(targets, t)
				}
			}
		}
	}

	if len(targets) == 0 {
		return nil
	}

	// Respect -l CLI flag: if TargetsFilePath already points to a real file,
	// it was set by the user on the command line and takes priority.
	if opts.TargetsFilePath != "" && fileutil.FileExists(opts.TargetsFilePath) {
		return nil
	}

	tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return fmt.Errorf("could not create temp targets file: %w", err)
	}
	for _, t := range targets {
		fmt.Fprintln(tmpFile, t)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("could not write temp targets file: %w", err)
	}

	internalTempFiles = append(internalTempFiles, tmpFile.Name())
	opts.TargetsFilePath = tmpFile.Name()
	return nil
}

// applyInlineSecrets handles the "secrets" key, which mirrors the format of a
// standalone secrets file. The section is serialised back to YAML, written to a
// temporary file, and that path is appended to opts.SecretsFile so the existing
// FileAuthProvider picks it up without modification.
//
// Example config YAML section:
//
//	secrets:
//	  static:
//	    - type: header
//	      domains:
//	        - api.example.com
//	      headers:
//	        - key: X-Api-Key
//	          value: my-secret-key
//	  dynamic:
//	    - template: custom-oauth-flow.yaml
//	      variables:
//	        - name: username
//	          value: pdteam
//	        - name: password
//	          value: secret
//	      type: cookie
//	      domains:
//	        - .*.example.com
//	      headers:
//	        - key: Authorization
//	          value: Bearer {{token}}
func applyInlineSecrets(raw map[string]interface{}, opts *types.Options) error {
	secretsVal, ok := raw["secrets"]
	if !ok {
		return nil
	}

	secretsData, err := yaml.Marshal(secretsVal)
	if err != nil {
		return fmt.Errorf("could not serialise inline secrets: %w", err)
	}

	tmpFile, err := os.CreateTemp("", "nuclei-secrets-*.yaml")
	if err != nil {
		return fmt.Errorf("could not create temp secrets file: %w", err)
	}
	if _, err := tmpFile.Write(secretsData); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("could not write temp secrets file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("could not close temp secrets file: %w", err)
	}

	internalTempFiles = append(internalTempFiles, tmpFile.Name())
	opts.SecretsFile = append(opts.SecretsFile, tmpFile.Name())
	return nil
}
