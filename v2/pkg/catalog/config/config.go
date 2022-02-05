package config

import (
	"os"
	"path/filepath"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/gologger"
)

// Config contains the internal nuclei engine configuration
type Config struct {
	TemplatesDirectory string `json:"nuclei-templates-directory,omitempty"`
	TemplateVersion    string `json:"nuclei-templates-version,omitempty"`
	NucleiVersion      string `json:"nuclei-version,omitempty"`
	NucleiIgnoreHash   string `json:"nuclei-ignore-hash,omitempty"`

	NucleiLatestVersion          string `json:"nuclei-latest-version"`
	NucleiTemplatesLatestVersion string `json:"nuclei-templates-latest-version"`
}

// nucleiConfigFilename is the filename of nuclei configuration file.
const nucleiConfigFilename = ".templates-config.json"

// Version is the current version of nuclei
const Version = `2.6.0`

func getConfigDetails() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "could not get home directory")
	}
	configDir := filepath.Join(homeDir, ".config", "nuclei")
	_ = os.MkdirAll(configDir, 0755)
	templatesConfigFile := filepath.Join(configDir, nucleiConfigFilename)
	return templatesConfigFile, nil
}

// ReadConfiguration reads the nuclei configuration file from disk.
func ReadConfiguration() (*Config, error) {
	templatesConfigFile, err := getConfigDetails()
	if err != nil {
		return nil, err
	}

	file, err := os.Open(templatesConfigFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	config := &Config{}
	if err := jsoniter.NewDecoder(file).Decode(config); err != nil {
		return nil, err
	}
	return config, nil
}

// WriteConfiguration writes the updated nuclei configuration to disk
func WriteConfiguration(config *Config) error {
	config.NucleiVersion = Version

	templatesConfigFile, err := getConfigDetails()
	if err != nil {
		return err
	}
	file, err := os.OpenFile(templatesConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	err = jsoniter.NewEncoder(file).Encode(config)
	if err != nil {
		return err
	}
	return nil
}

const nucleiIgnoreFile = ".nuclei-ignore"

// IgnoreFile is an internal nuclei template blocking configuration file
type IgnoreFile struct {
	Tags  []string `yaml:"tags"`
	Files []string `yaml:"files"`
}

// ReadIgnoreFile reads the nuclei ignore file returning blocked tags and paths
func ReadIgnoreFile() IgnoreFile {
	file, err := os.Open(getIgnoreFilePath())
	if err != nil {
		gologger.Error().Msgf("Could not read nuclei-ignore file: %s\n", err)
		return IgnoreFile{}
	}
	defer file.Close()

	ignore := IgnoreFile{}
	if err := yaml.NewDecoder(file).Decode(&ignore); err != nil {
		gologger.Error().Msgf("Could not parse nuclei-ignore file: %s\n", err)
		return IgnoreFile{}
	}
	return ignore
}

var (
	// customIgnoreFilePath contains a custom path for the ignore file
	customIgnoreFilePath string
	// ErrCustomIgnoreFilePathNotExist is raised when the ignore file doesn't exist in the custom path
	ErrCustomIgnoreFilePathNotExist = errors.New("Ignore file doesn't exist in custom path")
	// ErrCustomFolderNotExist is raised when the custom ignore folder doesn't exist
	ErrCustomFolderNotExist = errors.New("The custom ignore path doesn't exist")
)

// OverrideIgnoreFilePath with a custom existing folder
func OverrideIgnoreFilePath(customPath string) error {
	// custom path does not exist
	if !fileutil.FolderExists(customPath) {
		return ErrCustomFolderNotExist
	}
	// ignore file within the custom path does not exist
	if !fileutil.FileExists(filepath.Join(customPath, nucleiIgnoreFile)) {
		return ErrCustomIgnoreFilePathNotExist
	}
	customIgnoreFilePath = customPath
	return nil
}

// getIgnoreFilePath returns the ignore file path for the runner
func getIgnoreFilePath() string {
	var defIgnoreFilePath string

	if customIgnoreFilePath != "" {
		defIgnoreFilePath = filepath.Join(customIgnoreFilePath, nucleiIgnoreFile)
		return defIgnoreFilePath
	}

	home, err := os.UserHomeDir()
	if err == nil {
		configDir := filepath.Join(home, ".config", "nuclei")
		_ = os.MkdirAll(configDir, 0755)

		defIgnoreFilePath = filepath.Join(configDir, nucleiIgnoreFile)
		return defIgnoreFilePath
	}
	cwd, err := os.Getwd()
	if err != nil {
		return defIgnoreFilePath
	}
	cwdIgnoreFilePath := filepath.Join(cwd, nucleiIgnoreFile)
	return cwdIgnoreFilePath
}
