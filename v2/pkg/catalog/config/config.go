package config

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
)

// Config contains the internal nuclei engine configuration
type Config struct {
	TemplatesDirectory string `json:"nuclei-templates-directory,omitempty"`

	CustomS3TemplatesDirectory     string `json:"custom-s3-templates-directory"`
	CustomGithubTemplatesDirectory string `json:"custom-github-templates-directory"`

	TemplateVersion  string `json:"nuclei-templates-version,omitempty"`
	NucleiVersion    string `json:"nuclei-version,omitempty"`
	NucleiIgnoreHash string `json:"nuclei-ignore-hash,omitempty"`

	NucleiLatestVersion          string `json:"nuclei-latest-version"`
	NucleiTemplatesLatestVersion string `json:"nuclei-templates-latest-version"`
}

// nucleiConfigFilename is the filename of nuclei configuration file.
const nucleiConfigFilename = ".templates-config.json"

// Version is the current version of nuclei
const Version = `2.9.2-dev`

const nucleiIgnoreFile = ".nuclei-ignore"

// IgnoreFile is an internal nuclei template blocking configuration file
type IgnoreFile struct {
	Tags  []string `yaml:"tags"`
	Files []string `yaml:"files"`
}

// ReadIgnoreFile reads the nuclei ignore file returning blocked tags and paths
func ReadIgnoreFile() IgnoreFile {
	file, err := os.Open(DefaultConfig.GetIgnoreFilePath())
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
