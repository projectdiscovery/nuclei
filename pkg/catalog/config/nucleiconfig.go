package config

import (
	"bytes"
	"crypto/md5"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/utils/env"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
)

// DefaultConfig is the default nuclei configuration
// all config values and default are centralized here
var DefaultConfig *Config

type Config struct {
	TemplatesDirectory string `json:"nuclei-templates-directory,omitempty"`

	// customtemplates exists in templates directory with the name of custom-templates provider
	// below custom paths are absolute paths to respective custom-templates directories
	CustomS3TemplatesDirectory     string `json:"custom-s3-templates-directory"`
	CustomGitHubTemplatesDirectory string `json:"custom-github-templates-directory"`
	CustomGitLabTemplatesDirectory string `json:"custom-gitlab-templates-directory"`
	CustomAzureTemplatesDirectory  string `json:"custom-azure-templates-directory"`

	TemplateVersion        string `json:"nuclei-templates-version,omitempty"`
	NucleiIgnoreHash       string `json:"nuclei-ignore-hash,omitempty"`
	LogAllEvents           bool   `json:"-"` // when enabled logs all events (more than verbose)
	HideTemplateSigWarning bool   `json:"-"` // when enabled disables template signature warning

	// LatestXXX are not meant to be used directly and is used as
	// local cache of nuclei version check endpoint
	// these fields are only update during nuclei version check
	// TODO: move these fields to a separate unexported struct as they are not meant to be used directly
	LatestNucleiVersion          string `json:"nuclei-latest-version"`
	LatestNucleiTemplatesVersion string `json:"nuclei-templates-latest-version"`
	LatestNucleiIgnoreHash       string `json:"nuclei-latest-ignore-hash,omitempty"`

	// internal / unexported fields
	disableUpdates bool     `json:"-"` // disable updates both version check and template updates
	homeDir        string   `json:"-"` //  User Home Directory
	configDir      string   `json:"-"` //  Nuclei Global Config Directory
	debugArgs      []string `json:"-"` // debug args
}

// IsCustomTemplate determines whether a given template is custom-built or part of the official Nuclei templates.
// It checks if the template's path matches any of the predefined custom template directories
// (such as S3, GitHub, GitLab, and Azure directories). If the template resides in any of these directories,
// it is considered custom. Additionally, if the template's path does not start with the main Nuclei TemplatesDirectory,
// it is also considered custom. This function assumes that template paths are either absolute
// or relative to the same base as the paths configured in DefaultConfig.
func (c *Config) IsCustomTemplate(templatePath string) bool {
	customDirs := []string{
		c.CustomS3TemplatesDirectory,
		c.CustomGitHubTemplatesDirectory,
		c.CustomGitLabTemplatesDirectory,
		c.CustomAzureTemplatesDirectory,
	}

	for _, dir := range customDirs {
		if strings.HasPrefix(templatePath, dir) {
			return true
		}
	}
	return !strings.HasPrefix(templatePath, c.TemplatesDirectory)
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

// GetTemplateDir returns the nuclei templates directory absolute path
func (c *Config) GetTemplateDir() string {
	val, _ := filepath.Abs(c.TemplatesDirectory)
	return val
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

// NeedsIgnoreFileUpdate returns true if Ignore file hash is different (aka ignore file is outdated)
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

// GetKeysDir returns the nuclei signer keys directory
func (c *Config) GetKeysDir() string {
	return filepath.Join(c.configDir, "keys")
}

// GetAllCustomTemplateDirs returns all custom template directories
func (c *Config) GetAllCustomTemplateDirs() []string {
	return []string{c.CustomS3TemplatesDirectory, c.CustomGitHubTemplatesDirectory, c.CustomGitLabTemplatesDirectory, c.CustomAzureTemplatesDirectory}
}

// GetReportingConfigFilePath returns the nuclei reporting config file path
func (c *Config) GetReportingConfigFilePath() string {
	return filepath.Join(c.configDir, ReportingConfigFilename)
}

// GetIgnoreFilePath returns the nuclei ignore file path
func (c *Config) GetIgnoreFilePath() string {
	return filepath.Join(c.configDir, NucleiIgnoreFileName)
}

func (c *Config) GetTemplateIndexFilePath() string {
	return filepath.Join(c.TemplatesDirectory, NucleiTemplatesIndexFileName)
}

// GetChecksumFilePath returns checksum file path of nuclei templates
func (c *Config) GetChecksumFilePath() string {
	return filepath.Join(c.TemplatesDirectory, NucleiTemplatesCheckSumFileName)
}

// GetFlagsConfigFilePath returns the nuclei cli config file path
func (c *Config) GetFlagsConfigFilePath() string {
	return filepath.Join(c.configDir, CLIConfigFileName)
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

// GetCacheDir returns the nuclei cache directory
// with new version of nuclei cache directory is changed
// instead of saving resume files in nuclei config directory
// they are saved in nuclei cache directory
func (c *Config) GetCacheDir() string {
	return folderutil.AppCacheDirOrDefault(".nuclei-cache", BinaryName)
}

// SetConfigDir sets the nuclei configuration directory
// and appropriate changes are made to the config
func (c *Config) SetConfigDir(dir string) {
	c.configDir = dir
	if err := c.createConfigDirIfNotExists(); err != nil {
		gologger.Fatal().Msgf("Could not create nuclei config directory at %s: %s", c.configDir, err)
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
	c.CustomGitHubTemplatesDirectory = filepath.Join(dirPath, CustomGitHubTemplatesDirName)
	c.CustomS3TemplatesDirectory = filepath.Join(dirPath, CustomS3TemplatesDirName)
	c.CustomGitLabTemplatesDirectory = filepath.Join(dirPath, CustomGitLabTemplatesDirName)
	c.CustomAzureTemplatesDirectory = filepath.Join(dirPath, CustomAzureTemplatesDirName)
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
	c.TemplatesDirectory = cfg.TemplatesDirectory
	c.TemplateVersion = cfg.TemplateVersion
	c.NucleiIgnoreHash = cfg.NucleiIgnoreHash
	c.LatestNucleiIgnoreHash = cfg.LatestNucleiIgnoreHash
	c.LatestNucleiTemplatesVersion = cfg.LatestNucleiTemplatesVersion
	return nil
}

// WriteTemplatesConfig writes the nuclei templates config file
func (c *Config) WriteTemplatesConfig() error {
	// check if config folder exists if not create one
	if err := c.createConfigDirIfNotExists(); err != nil {
		return err
	}
	bin, err := json.Marshal(c)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to marshal nuclei config")
	}
	if err = os.WriteFile(c.getTemplatesConfigFilePath(), bin, 0600); err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to write nuclei config file at %s", c.getTemplatesConfigFilePath())
	}
	return nil
}

// WriteTemplatesIndex writes the nuclei templates index file
func (c *Config) WriteTemplatesIndex(index map[string]string) error {
	indexFile := c.GetTemplateIndexFilePath()
	var buff bytes.Buffer
	for k, v := range index {
		_, _ = buff.WriteString(k + "," + v + "\n")
	}
	return os.WriteFile(indexFile, buff.Bytes(), 0600)
}

// getTemplatesConfigFilePath returns configDir/.templates-config.json file path
func (c *Config) getTemplatesConfigFilePath() string {
	return filepath.Join(c.configDir, TemplateConfigFileName)
}

// createConfigDirIfNotExists creates the nuclei config directory if not exists
func (c *Config) createConfigDirIfNotExists() error {
	if !fileutil.FolderExists(c.configDir) {
		if err := fileutil.CreateFolder(c.configDir); err != nil {
			return errorutil.NewWithErr(err).Msgf("could not create nuclei config directory at %s", c.configDir)
		}
	}
	return nil
}

// copyIgnoreFile copies the nuclei ignore file default config directory
// to the current config directory
func (c *Config) copyIgnoreFile() {
	if err := c.createConfigDirIfNotExists(); err != nil {
		gologger.Error().Msgf("Could not create nuclei config directory at %s: %s", c.configDir, err)
		return
	}
	ignoreFilePath := c.GetIgnoreFilePath()
	if !fileutil.FileExists(ignoreFilePath) {
		// copy ignore file from default config directory
		if err := fileutil.CopyFile(filepath.Join(folderutil.AppConfigDirOrDefault(FallbackConfigFolderName, BinaryName), NucleiIgnoreFileName), ignoreFilePath); err != nil {
			gologger.Error().Msgf("Could not copy nuclei ignore file at %s: %s", ignoreFilePath, err)
		}
	}
}

// IsDebugArgEnabled checks if debug arg is enabled
// this could be a feature specific to debugging like PPROF or printing stats
// of max host error etc
func (c *Config) IsDebugArgEnabled(arg string) bool {
	for _, v := range c.debugArgs {
		if v == arg {
			return true
		}
	}
	return false
}

// parseDebugArgs from string
func (c *Config) parseDebugArgs(data string) {
	// use space as seperator instead of commas
	tmp := strings.Fields(data)
	for _, v := range tmp {
		key := v
		value := ""
		// if it is key value pair then split it
		if strings.Contains(v, "=") {
			parts := strings.SplitN(v, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key, value = strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		}
		if value == "false" || value == "0" {
			// if false or disabled then skip
			continue
		}
		switch key {
		case DebugArgHostErrorStats:
			c.debugArgs = append(c.debugArgs, DebugArgHostErrorStats)
		case DebugExportURLPattern:
			c.debugArgs = append(c.debugArgs, DebugExportURLPattern)
		}
	}
}

func init() {
	// first attempt to migrate all files from old config directory to new config directory
	goflags.AttemptConfigMigration() // regardless how many times this is called it will only migrate once based on condition

	ConfigDir := folderutil.AppConfigDirOrDefault(FallbackConfigFolderName, BinaryName)

	if cfgDir := os.Getenv(NucleiConfigDirEnv); cfgDir != "" {
		ConfigDir = cfgDir
	}

	// create config directory if not exists
	if !fileutil.FolderExists(ConfigDir) {
		if err := fileutil.CreateFolder(ConfigDir); err != nil {
			gologger.Error().Msgf("failed to create config directory at %v got: %s", ConfigDir, err)
		}
	}
	DefaultConfig = &Config{
		homeDir:   folderutil.HomeDirOrDefault(""),
		configDir: ConfigDir,
	}

	// when enabled will log events in more verbosity than -v or -debug
	// ex: N templates are excluded
	// with this switch enabled nuclei will print details of above N templates
	if value := env.GetEnvOrDefault("NUCLEI_LOG_ALL", false); value {
		DefaultConfig.LogAllEvents = true
	}
	if value := env.GetEnvOrDefault("HIDE_TEMPLATE_SIG_WARNING", false); value {
		DefaultConfig.HideTemplateSigWarning = true
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
	// attempt to migrate resume files
	// this also happens once regardless of how many times this is called
	migrateResumeFiles()
	// Loads/updates paths of custom templates
	// Note: custom templates paths should not be updated in config file
	// and even if it is changed we don't follow it since it is not expected behavior
	// If custom templates are in default locations only then they are loaded while running nuclei
	DefaultConfig.SetTemplatesDir(DefaultConfig.TemplatesDirectory)
	DefaultConfig.parseDebugArgs(env.GetEnvOrDefault("NUCLEI_ARGS", ""))
}

// Add Default Config adds default when .templates-config.json file is not present
func applyDefaultConfig() {
	DefaultConfig.TemplatesDirectory = filepath.Join(DefaultConfig.homeDir, NucleiTemplatesDirName)
	// updates all necessary paths
	DefaultConfig.SetTemplatesDir(DefaultConfig.TemplatesDirectory)
}

func migrateResumeFiles() {
	// attempt to migrate old resume files to new directory structure
	// after migration has been done in goflags
	oldResumeDir := DefaultConfig.GetConfigDir()
	// migrate old resume file to new directory structure
	if !fileutil.FileOrFolderExists(DefaultConfig.GetCacheDir()) && fileutil.FileOrFolderExists(oldResumeDir) {
		// this means new cache dir doesn't exist, so we need to migrate
		// first check if old resume file exists if not then no need to migrate
		exists := false
		files, err := os.ReadDir(oldResumeDir)
		if err != nil {
			// log silently
			log.Printf("could not read old resume dir: %s\n", err)
			return
		}
		for _, file := range files {
			if strings.HasSuffix(file.Name(), ".cfg") {
				exists = true
				break
			}
		}
		if !exists {
			// no need to migrate
			return
		}

		// create new cache dir
		err = os.MkdirAll(DefaultConfig.GetCacheDir(), os.ModePerm)
		if err != nil {
			// log silently
			log.Printf("could not create new cache dir: %s\n", err)
			return
		}
		err = filepath.WalkDir(oldResumeDir, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".cfg") {
				return nil
			}
			err = os.Rename(path, filepath.Join(DefaultConfig.GetCacheDir(), filepath.Base(path)))
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			// log silently
			log.Printf("could not migrate old resume files: %s\n", err)
			return
		}

	}
}
