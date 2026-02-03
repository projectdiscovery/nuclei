package config

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	fileutil "github.com/projectdiscovery/utils/file"
)

// ProfileConfig represents a template profile configuration with metadata.
type ProfileConfig struct {
	Name        string                 `yaml:"name,omitempty"`
	Purpose     string                 `yaml:"purpose,omitempty"`
	Description string                 `yaml:"description,omitempty"`
	Config      map[string]interface{} `yaml:",inline"`
}

// LoadProfileConfig loads and processes a profile configuration file.
func LoadProfileConfig(profilePath string) (map[string]interface{}, error) {
	if !fileutil.FileExists(profilePath) {
		return nil, fmt.Errorf("profile file does not exist: %s", profilePath)
	}

	data, err := os.ReadFile(profilePath)
	if err != nil {
		return nil, fmt.Errorf("could not read profile file: %w", err)
	}

	var profile ProfileConfig
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return nil, fmt.Errorf("could not parse profile YAML: %w", err)
	}

	processedConfig, err := processInlineContent(profile.Config)
	if err != nil {
		return nil, fmt.Errorf("could not process inline content: %w", err)
	}

	return processedConfig, nil
}

// processInlineContent processes inline content in config maps.
func processInlineContent(config map[string]interface{}) (map[string]interface{}, error) {
	processed := make(map[string]interface{})

	for key, value := range config {
		switch v := value.(type) {
		case string:
			processed[key] = processStringValue(v)
		case []interface{}:
			processed[key] = v
		case map[string]interface{}:
			nestedProcessed, err := processInlineContent(v)
			if err != nil {
				return nil, err
			}
			processed[key] = nestedProcessed
		default:
			processed[key] = v
		}
	}

	return processed, nil
}

// processStringValue converts multi-line strings to slices.
func processStringValue(value string) interface{} {
	if strings.Contains(value, "\n") {
		lines := strings.Split(value, "\n")
		var nonEmptyLines []string
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				nonEmptyLines = append(nonEmptyLines, trimmed)
			}
		}
		if len(nonEmptyLines) > 1 {
			return nonEmptyLines
		}
		if len(nonEmptyLines) == 1 {
			return nonEmptyLines[0]
		}
		return ""
	}
	return value
}

// WriteConfigToTempFile writes config to a temporary YAML file.
func WriteConfigToTempFile(config map[string]interface{}) (string, error) {
	tmpFile, err := os.CreateTemp("", "nuclei-profile-*.yaml")
	if err != nil {
		return "", fmt.Errorf("could not create temporary file: %w", err)
	}
	defer tmpFile.Close()

	encoder := yaml.NewEncoder(tmpFile)
	encoder.SetIndent(2)
	if err := encoder.Encode(config); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("could not write config to temporary file: %w", err)
	}

	return tmpFile.Name(), nil
}

// ProcessSecretsConfig extracts embedded secrets to a temporary file.
func ProcessSecretsConfig(config map[string]interface{}) (string, error) {
	secretsData, ok := config["secrets"]
	if !ok {
		return "", nil
	}

	delete(config, "secrets")

	secretsMap, ok := secretsData.(map[string]interface{})
	if !ok {
		return "", nil
	}

	tmpFile, err := os.CreateTemp("", "nuclei-secrets-*.yaml")
	if err != nil {
		return "", fmt.Errorf("could not create temporary secrets file: %w", err)
	}
	defer tmpFile.Close()

	encoder := yaml.NewEncoder(tmpFile)
	encoder.SetIndent(2)
	if err := encoder.Encode(secretsMap); err != nil {
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("could not write secrets to temporary file: %w", err)
	}

	return tmpFile.Name(), nil
}

// ProcessTargetList converts inline target lists to temporary files.
func ProcessTargetList(config map[string]interface{}) error {
	if listData, ok := config["list"]; ok {
		switch v := listData.(type) {
		case string:
			if strings.Contains(v, "\n") {
				tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
				if err != nil {
					return fmt.Errorf("could not create temporary targets file: %w", err)
				}

				_, err = tmpFile.WriteString(v)
				tmpFile.Close()
				if err != nil {
					os.Remove(tmpFile.Name())
					return fmt.Errorf("could not write targets to temporary file: %w", err)
				}

				config["list"] = tmpFile.Name()
				config["_target_list_file"] = tmpFile.Name()
			}
		case []interface{}:
			tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
			if err != nil {
				return fmt.Errorf("could not create temporary targets file: %w", err)
			}

			writer := bufio.NewWriter(tmpFile)
			for _, item := range v {
				if str, ok := item.(string); ok {
					_, err := writer.WriteString(str + "\n")
					if err != nil {
						tmpFile.Close()
						os.Remove(tmpFile.Name())
						return fmt.Errorf("could not write targets to temporary file: %w", err)
					}
				}
			}
			writer.Flush()
			tmpFile.Close()

			config["list"] = tmpFile.Name()
			config["_target_list_file"] = tmpFile.Name()
		case []string:
			tmpFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
			if err != nil {
				return fmt.Errorf("could not create temporary targets file: %w", err)
			}

			writer := bufio.NewWriter(tmpFile)
			for _, str := range v {
				_, err := writer.WriteString(str + "\n")
				if err != nil {
					tmpFile.Close()
					os.Remove(tmpFile.Name())
					return fmt.Errorf("could not write targets to temporary file: %w", err)
				}
			}
			writer.Flush()
			tmpFile.Close()

			config["list"] = tmpFile.Name()
			config["_target_list_file"] = tmpFile.Name()
		}
	}

	return nil
}

// LoadAndProcessProfile loads and processes a profile with all features.
func LoadAndProcessProfile(profilePath string) (map[string]interface{}, string, error) {
	config, err := LoadProfileConfig(profilePath)
	if err != nil {
		return nil, "", err
	}

	if err := ProcessTargetList(config); err != nil {
		return nil, "", err
	}

	secretsFile, err := ProcessSecretsConfig(config)
	if err != nil {
		return nil, "", err
	}

	if secretsFile != "" {
		config["_embedded_secrets_file"] = secretsFile
	}

	return config, secretsFile, nil
}

// ConvertConfigToFile converts config to a temporary YAML file for goflags.
func ConvertConfigToFile(config map[string]interface{}) (string, error) {
	cleanConfig := make(map[string]interface{})
	for k, v := range config {
		if !strings.HasPrefix(k, "_") {
			cleanConfig[k] = v
		}
	}

	return WriteConfigToTempFile(cleanConfig)
}
