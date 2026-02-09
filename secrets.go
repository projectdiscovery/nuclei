package types

import (
	"os"

	"gopkg.in/yaml.v3"
)

// ProcessSecrets checks if any secrets were provided in the YAML config.
// If they were, it saves them to a temporary file and tells Nuclei to use that file.
func (options *Options) ProcessSecrets() error {
	if options.Secrets == nil {
		return nil
	}

	// 1. Convert the secrets data back into YAML format
	data, err := yaml.Marshal(options.Secrets)
	if err != nil {
		return err
	}

	// 2. Create a temporary file (like a "ghost" file)
	f, err := os.CreateTemp("", "nuclei-secrets-*.yaml")
	if err != nil {
		return err
	}
	// We don't defer os.Remove here because Nuclei needs to read it later.
	// In a full implementation, we might want to clean this up on exit.
	defer f.Close()

	// 3. Write the secrets to the ghost file
	if _, err := f.Write(data); err != nil {
		return err
	}

	options.SecretsFile = append(options.SecretsFile, f.Name())
	
	return nil
}