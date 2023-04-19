package config

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
)

// DefaultConfig is the default nuclei configuration
// all config values and default are centralized here
var DefaultConfig *Config

type Config struct {
	TemplatesDirectory string `json:"nuclei-templates-directory,omitempty"`

	CustomS3TemplatesDirectory     string `json:"custom-s3-templates-directory"`
	CustomGithubTemplatesDirectory string `json:"custom-github-templates-directory"`

	TemplateVersion  string `json:"nuclei-templates-version,omitempty"`
	NucleiIgnoreHash string `json:"nuclei-ignore-hash,omitempty"`

	// Latestxxx are not meant to be used directly and is used as
	// local cache of nuclei version check endpoint
	// these fields are only update during nuclei version check
	// TODO: move these fields to a separate unexported struct as they are not meant to be used directly
	LatestNucleiVersion          string `json:"nuclei-latest-version"`
	LatestNucleiTemplatesVersion string `json:"nuclei-templates-latest-version"`
	LatestNucleiIgnoreHash       string `json:"nuclei-latest-ignore-hash,omitempty"`

	// internal / unexported fields
	disableUpdates bool   `json:"-"` // disable updates both version check and template updates
	homeDir        string `json:"-"` //  User Home Directory
	configDir      string `json:"-"` //  Nuclei Global Config Directory
}

// WriteVersionCheckData writes version check data to config file
func (c *Config) WriteVersionCheckData(ignorehash, nucleiVersion, templatesVersion string) error {
	updated := false
	if ignorehash != "" && c.LatestNucleiIgnoreHash != ignorehash {
		c.LatestNucleiIgnoreHash = ignorehash
		updated = true
	}
	if nucleiVersion != "" && c.LatestNucleiVersion != nucleiVersion {
		c.LatestNucleiVersion = nucleiVersion
		updated = true
	}
	if templatesVersion != "" && c.LatestNucleiTemplatesVersion != templatesVersion {
		c.LatestNucleiTemplatesVersion = templatesVersion
		updated = true
	}
	// write config to disk if any of the fields are updated
	if updated {
		return c.WriteTemplatesConfig()
	}
	return nil
}

// DisableUpdateCheck disables update check and template updates
func (c *Config) DisableUpdateCheck() {
	c.disableUpdates = true
}

// CanCheckForUpdates returns true if update check is enabled
func (c *Config) CanCheckForUpdates() bool {
	return !c.disableUpdates
}

// NeedsTemplateUpdate returns true if template installation/update is required
func (c *Config) NeedsTemplateUpdate() bool {
	return !c.disableUpdates && (c.TemplateVersion == "" || IsOutdatedVersion(c.TemplateVersion, c.LatestNucleiTemplatesVersion) || !fileutil.FolderExists(c.TemplatesDirectory))
}

// NeedsIngoreFileUpdate returns true if Ignore file hash is different (aka ignore file is outdated)
func (c *Config) NeedsIgnoreFileUpdate() bool {
	return c.NucleiIgnoreHash == "" || c.NucleiIgnoreHash != c.LatestNucleiIgnoreHash
}

// UpdateNucleiIgnoreHash updates the nuclei ignore hash in config
func (c *Config) UpdateNucleiIgnoreHash() error {
	// calculate hash of ignore file and update config
	ignoreFilePath := c.GetIgnoreFilePath()
	if fileutil.FileExists(ignoreFilePath) {
		bin, err := os.ReadFile(ignoreFilePath)
		if err != nil {
			return errorutil.NewWithErr(err).Msgf("could not read nuclei ignore file")
		}
		c.NucleiIgnoreHash = fmt.Sprintf("%x", md5.Sum(bin))
		// write config to disk
		return c.WriteTemplatesConfig()
	}
	return errorutil.NewWithTag("config", "ignore file not found: could not update nuclei ignore hash")
}

// GetConfigDir returns the nuclei configuration directory
func (c *Config) GetConfigDir() string {
	return c.configDir
}

// GetReportingConfigFilePath returns the nuclei reporting config file path
func (c *Config) GetReportingConfigFilePath() string {
	return filepath.Join(c.configDir, ReportingConfigFilename)
}

// GetIgnoreFilePath returns the nuclei ignore file path
func (c *Config) GetIgnoreFilePath() string {
	return filepath.Join(c.configDir, NucleiIgnoreFileName)
}

// GetTemplatesConfigFilePath returns checksum file path of nuclei templates
func (c *Config) GetChecksumFilePath() string {
	return filepath.Join(c.TemplatesDirectory, NucleiTemplatesCheckSumFileName)
}

// GetCLIOptsConfigFilePath returns the nuclei cli config file path
func (c *Config) GetFlagsConfigFilePath() string {
	return filepath.Join(c.configDir, CLIConifgFileName)
}

// GetNewAdditions returns new template additions in current template release
// if .new-additions file is not present empty slice is returned
func (c *Config) GetNewAdditions() []string {
	arr := []string{}
	newAdditionsPath := filepath.Join(c.TemplatesDirectory, NewTemplateAdditionsFileName)
	if !fileutil.FileExists(newAdditionsPath) {
		return arr
	}
	bin, err := os.ReadFile(newAdditionsPath)
	if err != nil {
		return arr
	}
	for _, v := range strings.Fields(string(bin)) {
		if IsTemplate(v) {
			arr = append(arr, v)
		}
	}
	return arr
}

// SetConfigDir sets the nuclei configuration directory
// and appropriate changes are made to the config
func (c *Config) SetConfigDir(dir string) {
	c.configDir = dir
	if !fileutil.FolderExists(dir) {
		if err := fileutil.CreateFolder(dir); err != nil {
			gologger.Fatal().Msgf("Could not create nuclei config directory at %s: %s", dir, err)
		}
	}

	// if folder already exists read config or create new
	if err := c.ReadTemplatesConfig(); err != nil {
		// create new config
		applyDefaultConfig()
		if err2 := c.WriteTemplatesConfig(); err2 != nil {
			gologger.Fatal().Msgf("Could not create nuclei config file at %s: %s", c.getTemplatesConfigFilePath(), err2)
		}
	}

	// while other config files are optional, ignore file is mandatory
	// since it is used to ignore templates with weak matchers
	c.copyIgnoreFile()
}

// SetTemplatesDir sets the new nuclei templates directory
func (c *Config) SetTemplatesDir(dirPath string) {
	if dirPath != "" && !filepath.IsAbs(dirPath) {
		cwd, _ := os.Getwd()
		dirPath = filepath.Join(cwd, dirPath)
	}
	c.TemplatesDirectory = dirPath
	// Update the custom templates directory
	c.CustomGithubTemplatesDirectory = filepath.Join(dirPath, CustomGithubTemplatesDirName)
	c.CustomS3TemplatesDirectory = filepath.Join(dirPath, CustomGithubTemplatesDirName)
}

// SetTemplatesVersion sets the new nuclei templates version
func (c *Config) SetTemplatesVersion(version string) error {
	c.TemplateVersion = version
	// write config to disk
	if err := c.WriteTemplatesConfig(); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not write nuclei config file at %s", c.getTemplatesConfigFilePath())
	}
	return nil
}

// ReadTemplatesConfig reads the nuclei templates config file
func (c *Config) ReadTemplatesConfig() error {
	if !fileutil.FileExists(c.getTemplatesConfigFilePath()) {
		return errorutil.NewWithTag("config", "nuclei config file at %s does not exist", c.getTemplatesConfigFilePath())
	}
	var cfg *Config
	bin, err := os.ReadFile(c.getTemplatesConfigFilePath())
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("could not read nuclei config file at %s", c.getTemplatesConfigFilePath())
	}
	if err := json.Unmarshal(bin, &cfg); err != nil {
		return errorutil.NewWithErr(err).Msgf("could not unmarshal nuclei config file at %s", c.getTemplatesConfigFilePath())
	}
	// apply config
	c.CustomGithubTemplatesDirectory = cfg.CustomGithubTemplatesDirectory
	c.CustomS3TemplatesDirectory = cfg.CustomS3TemplatesDirectory
	c.TemplatesDirectory = cfg.TemplatesDirectory
	c.TemplateVersion = cfg.TemplateVersion
	c.NucleiIgnoreHash = cfg.NucleiIgnoreHash
	c.LatestNucleiIgnoreHash = cfg.LatestNucleiIgnoreHash
	c.LatestNucleiTemplatesVersion = cfg.LatestNucleiTemplatesVersion
	return nil
}

// WriteTemplatesConfig writes the nuclei templates config file
func (c *Config) WriteTemplatesConfig() error {
	bin, err := json.Marshal(c)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to marshal nuclei config")
	}
	if err = os.WriteFile(c.getTemplatesConfigFilePath(), bin, 0600); err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to write nuclei config file at %s", c.getTemplatesConfigFilePath())
	}
	return nil
}

// getTemplatesConfigFilePath returns configDir/.templates-config.json file path
func (c *Config) getTemplatesConfigFilePath() string {
	return filepath.Join(c.configDir, TemplateConfigFileName)
}

// copyIgnoreFile copies the nuclei ignore file default config directory
// to the current config directory
func (c *Config) copyIgnoreFile() {
	ignoreFilePath := c.GetIgnoreFilePath()
	if !fileutil.FileExists(ignoreFilePath) {
		// copy ignore file
		if err := fileutil.CopyFile(filepath.Join(getDefaultConfigDir(), NucleiIgnoreFileName), ignoreFilePath); err != nil {
			gologger.Error().Msgf("Could not copy nuclei ignore file at %s: %s", ignoreFilePath, err)
		}
	}
}

func init() {
	ConfigDir := getDefaultConfigDir()
	if !fileutil.FolderExists(ConfigDir) {
		if err := fileutil.CreateFolder(ConfigDir); err != nil {
			gologger.Error().Msgf("failed to create config directory at %v got: %s", ConfigDir, err)
		}
	}
	DefaultConfig = &Config{
		homeDir:   folderutil.HomeDirOrDefault(""),
		configDir: ConfigDir,
	}
	// try to read config from file
	if err := DefaultConfig.ReadTemplatesConfig(); err != nil {
		gologger.Verbose().Msgf("config file not found, creating new config file at %s", DefaultConfig.getTemplatesConfigFilePath())
		applyDefaultConfig()
		// write config to file
		if err := DefaultConfig.WriteTemplatesConfig(); err != nil {
			gologger.Error().Msgf("failed to write config file at %s got: %s", DefaultConfig.getTemplatesConfigFilePath(), err)
		}
	}
}

func getDefaultConfigDir() string {
	// Review Needed:  Earlier a dependency was used to locate home dir
	// i.e 	"github.com/mitchellh/go-homedir" not sure if it is needed
	// Even if such case exists it should be abstracted via below function call in utils/folder
	homedir := folderutil.HomeDirOrDefault("")
	// TBD: we should probably stick to specification and use config directories provided by distro
	// instead of manually creating one since $HOME/.config/ is config directory of Linux desktops
	// Ref: https://pkg.go.dev/os#UserConfigDir
	// some distros like NixOS or others have totally different config directories this causes issues for us (since we are not using os.UserConfigDir)
	userCfgDir := filepath.Join(homedir, ".config")
	return filepath.Join(userCfgDir, "nuclei")
}

// Add Default Config adds default when .templates-config.json file is not present
func applyDefaultConfig() {
	DefaultConfig.TemplatesDirectory = filepath.Join(DefaultConfig.homeDir, NucleiTemplatesDirName)
	DefaultConfig.CustomGithubTemplatesDirectory = filepath.Join(DefaultConfig.TemplatesDirectory, CustomGithubTemplatesDirName)
	DefaultConfig.CustomS3TemplatesDirectory = filepath.Join(DefaultConfig.TemplatesDirectory, CustomS3TemplatesDirName)
}
