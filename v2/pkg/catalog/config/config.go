package config

import (
	"os"
	"path"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v2"
)

// Config contains the internal nuclei engine configuration
type Config struct {
	TemplatesDirectory string    `json:"templates-directory,omitempty"`
	CurrentVersion     string    `json:"current-version,omitempty"`
	LastChecked        time.Time `json:"last-checked,omitempty"`
	IgnoreURL          string    `json:"ignore-url,omitempty"`
	NucleiVersion      string    `json:"nuclei-version,omitempty"`
	LastCheckedIgnore  time.Time `json:"last-checked-ignore,omitempty"`

	NucleiLatestVersion          string `json:"nuclei-latest-version"`
	NucleiTemplatesLatestVersion string `json:"nuclei-templates-latest-version"`
}

// nucleiConfigFilename is the filename of nuclei configuration file.
const nucleiConfigFilename = ".templates-config.json"

// Version is the current version of nuclei
const Version = `2.4.3-dev`

func getConfigDetails() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", errors.Wrap(err, "could not get home directory")
	}
	configDir := path.Join(homeDir, "/.config", "/nuclei")
	_ = os.MkdirAll(configDir, os.ModePerm)
	templatesConfigFile := path.Join(configDir, nucleiConfigFilename)
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
	err = jsoniter.NewDecoder(file).Decode(config)
	if err != nil {
		return nil, err
	}
	return config, nil
}

// WriteConfiguration writes the updated nuclei configuration to disk
func WriteConfiguration(config *Config, checked, checkedIgnore bool) error {
	if config.IgnoreURL == "" {
		config.IgnoreURL = "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/.nuclei-ignore"
	}
	if checked {
		config.LastChecked = time.Now()
	}
	if checkedIgnore {
		config.LastCheckedIgnore = time.Now()
	}
	config.NucleiVersion = Version

	templatesConfigFile, err := getConfigDetails()
	if err != nil {
		return err
	}
	file, err := os.OpenFile(templatesConfigFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0777)
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

// getIgnoreFilePath returns the ignore file path for the runner
func getIgnoreFilePath() string {
	var defIgnoreFilePath string

	home, err := os.UserHomeDir()
	if err == nil {
		configDir := path.Join(home, "/.config", "/nuclei")
		_ = os.MkdirAll(configDir, os.ModePerm)

		defIgnoreFilePath = path.Join(configDir, nucleiIgnoreFile)
		return defIgnoreFilePath
	}
	cwd, err := os.Getwd()
	if err != nil {
		return defIgnoreFilePath
	}
	cwdIgnoreFilePath := path.Join(cwd, nucleiIgnoreFile)
	return cwdIgnoreFilePath
}
