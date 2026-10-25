package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/adrg/xdg"
	"github.com/projectdiscovery/gologger"
	filepathutil "github.com/projectdiscovery/nuclei/v3/pkg/utils/filepath"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	"github.com/projectdiscovery/utils/env"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
)

// DefaultConfig is the default nuclei configuration
// all config values and default are centralized here
var DefaultConfig *Config

type Config struct {
	TemplatesDirectory string `json:"nuclei-templates-directory,omitempty"`

	// Custom template paths are absolute provider-specific directories under the
	// active template root.
	CustomS3TemplatesDirectory     string `json:"custom-s3-templates-directory"`
	CustomGitHubTemplatesDirectory string `json:"custom-github-templates-directory"`
	CustomGitLabTemplatesDirectory string `json:"custom-gitlab-templates-directory"`
	CustomAzureTemplatesDirectory  string `json:"custom-azure-templates-directory"`

	TemplateVersion string `json:"nuclei-templates-version,omitempty"`

	// NucleiIgnoreHash is retained for SDK compatibility. Nuclei derives the
	// current hash from the active ignore file and does not persist this field.
	//
	// Deprecated: local ignore-file hashes are derived from the active file.
	NucleiIgnoreHash       string `json:"-"`
	LogAllEvents           bool   `json:"-"` // when enabled logs all events (more than verbose)
	HideTemplateSigWarning bool   `json:"-"` // when enabled disables template signature warning

	// These fields cache version-check results.
	LatestNucleiVersion          string `json:"nuclei-latest-version"`
	LatestNucleiTemplatesVersion string `json:"nuclei-templates-latest-version"`

	// LatestNucleiIgnoreHash is retained for SDK compatibility. Nuclei passes
	// remote ignore hashes directly from version checks to the active-file
	// comparison and does not persist this field.
	//
	// Deprecated: remote ignore hashes are transient version-check results.
	LatestNucleiIgnoreHash string           `json:"-"`
	Logger                 *gologger.Logger `json:"-"` // logger

	// internal / unexported fields
	disableUpdates    bool     `json:"-"` // disable updates both version check and template updates
	configDir         string   `json:"-"` //  Nuclei Global Config Directory
	stateDir          string   `json:"-"` // Restart-persistent operational state
	cacheDir          string   `json:"-"` // Regenerable cached data
	dataHome          string   `json:"-"` // User template data
	dataDirs          []string `json:"-"` // Template data, in preference order
	debugArgs         []string `json:"-"` // debug args
	initializationErr error    `json:"-"`

	m sync.Mutex
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
		if dir != "" && filepathutil.IsPathWithinDirectory(templatePath, dir) {
			return true
		}
	}

	if c.TemplatesDirectory == "" {
		return false
	}

	return !filepathutil.IsPathWithinDirectory(templatePath, c.TemplatesDirectory)
}

// WriteVersionCheckData writes version check data to config file
func (c *Config) WriteVersionCheckData(ignoreHash, nucleiVersion, templatesVersion string) error {
	updated := false

	if ignoreHash != "" && c.LatestNucleiIgnoreHash != ignoreHash {
		// Retain the historical in-memory SDK behavior without persisting remote
		// ignore metadata.
		c.LatestNucleiIgnoreHash = ignoreHash
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
	c.m.Lock()
	defer c.m.Unlock()

	c.disableUpdates = true
}

// CanCheckForUpdates returns true if update check is enabled
func (c *Config) CanCheckForUpdates() bool {
	c.m.Lock()
	defer c.m.Unlock()

	return !c.disableUpdates
}

// NeedsTemplateUpdate returns true if template installation/update is required
func (c *Config) NeedsTemplateUpdate() bool {
	c.m.Lock()
	defer c.m.Unlock()

	return !c.disableUpdates &&
		(c.TemplateVersion == "" || IsOutdatedVersion(c.TemplateVersion, c.LatestNucleiTemplatesVersion) || !fileutil.FolderExists(c.TemplatesDirectory))
}

// GetConfigDir returns the nuclei configuration directory
func (c *Config) GetConfigDir() string {
	return c.configDir
}

// GetStateDir returns the directory for restart-persistent operational state.
func (c *Config) GetStateDir() string {
	if c.stateDir != "" {
		return c.stateDir
	}

	return defaultStateDir()
}

// SetStateDir changes the templates state directory. It is primarily useful to
// SDK callers that isolate all Nuclei storage.
func (c *Config) SetStateDir(dir string) {
	c.stateDir = dir
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
//
// Deprecated: use GetActiveIgnoreFilePath. The config-directory ignore file is
// no longer active.
func (c *Config) GetIgnoreFilePath() string {
	return filepath.Join(c.configDir, NucleiIgnoreFileName)
}

// GetActiveIgnoreFilePath returns the ignore file in the active public template
// root.
func (c *Config) GetActiveIgnoreFilePath() string {
	return filepath.Join(c.TemplatesDirectory, NucleiIgnoreFileName)
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

	for v := range strings.FieldsSeq(string(bin)) {
		if IsTemplateWithRoot(v, c.TemplatesDirectory) {
			arr = append(arr, v)
		}
	}

	return arr
}

// GetCacheDir returns the directory for regenerable cached data.
func (c *Config) GetCacheDir() string {
	if c.cacheDir != "" {
		return c.cacheDir
	}

	return defaultCacheDir()
}

// SetConfigDir sets the nuclei configuration directory
// and appropriate changes are made to the config
func (c *Config) SetConfigDir(dir string) {
	c.configDir = dir
	// Preserve the historical SDK behavior that SetConfigDir also isolates
	// templates state. NUCLEI_CONFIG_DIR is resolved separately and does not move
	// state.
	c.stateDir = dir
	if err := c.createConfigDirIfNotExists(); err != nil {
		c.Logger.Fatal().Msgf("Could not create nuclei config directory at %s: %s", c.configDir, err)
	}

	// if folder already exists read config or create new
	if err := c.ReadTemplatesConfig(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			c.Logger.Fatal().Msgf("Could not read templates state: %s", err)
		}

		// create new config
		if defaultsErr := c.applyDefaultConfig(); defaultsErr != nil {
			c.Logger.Fatal().Msgf("Could not select default templates directory: %s", defaultsErr)
		}

		if err2 := c.WriteTemplatesConfig(); err2 != nil {
			c.Logger.Fatal().Msgf("Could not create nuclei config file at %s: %s", c.getTemplatesConfigFilePath(), err2)
		}
	}
}

// SetTemplatesDir sets the new nuclei templates directory
func (c *Config) SetTemplatesDir(dirPath string) {
	c.setTemplatesDir(dirPath)
}

func (c *Config) setTemplatesDir(dirPath string) {
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
		return errkit.Newf("could not write nuclei config file at %s: %v", c.getTemplatesConfigFilePath(), err)
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

// createConfigDirIfNotExists creates the nuclei config directory if not exists
func (c *Config) createConfigDirIfNotExists() error {
	if !fileutil.FolderExists(c.configDir) {
		if err := fileutil.CreateFolder(c.configDir); err != nil {
			return errkit.Newf("could not create nuclei config directory at %s: %v", c.configDir, err)
		}
	}
	return nil
}

// IsDebugArgEnabled checks if debug arg is enabled
// this could be a feature specific to debugging like PPROF or printing stats
// of max host error etc
func (c *Config) IsDebugArgEnabled(arg string) bool {
	return slices.Contains(c.debugArgs, arg)
}

// parseDebugArgs from string
func (c *Config) parseDebugArgs(data string) {
	// use space as separator instead of commas
	for v := range strings.FieldsSeq(data) {
		key := v
		value := ""

		// if it is key value pair then split it
		if k, val, ok := strings.Cut(v, "="); ok {
			key, value = strings.TrimSpace(k), strings.TrimSpace(val)
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
	ConfigDir := defaultConfigDir()

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
		configDir: ConfigDir,
		stateDir:  defaultStateDir(),
		cacheDir:  defaultCacheDir(),
		dataHome:  xdg.DataHome,
		dataDirs:  append([]string(nil), xdg.DataDirs...),
		Logger:    gologger.DefaultLogger,
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
		if !errors.Is(err, os.ErrNotExist) {
			DefaultConfig.initializationErr = err
			gologger.Error().Msgf("Failed to read templates state: %s", err)
		} else {
			gologger.Verbose().Msgf("Templates state not found, creating %s", DefaultConfig.getTemplatesConfigFilePath())
		}

		if defaultsErr := DefaultConfig.applyDefaultConfig(); defaultsErr != nil {
			DefaultConfig.initializationErr = errors.Join(DefaultConfig.initializationErr, defaultsErr)
			gologger.Error().Msgf("Failed to select default templates directory: %s", defaultsErr)
		} else if DefaultConfig.initializationErr == nil {
			if writeErr := DefaultConfig.WriteTemplatesConfig(); writeErr != nil {
				DefaultConfig.initializationErr = writeErr
				gologger.Error().Msgf("Failed to write templates state at %s: %s", DefaultConfig.getTemplatesConfigFilePath(), writeErr)
			}
		}
	}

	DefaultConfig.parseDebugArgs(env.GetEnvOrDefault("NUCLEI_ARGS", ""))

	// expose the templates directory to the yaml preprocessor so include
	// directives can be confined to it without yaml importing this package
	// (which would create an import cycle).
	yaml.TemplateBaseDirProvider = func() string {
		return DefaultConfig.GetTemplateDir()
	}
}

// InitializationError returns a templates state or path error detected during
// package initialization.
func (c *Config) InitializationError() error {
	return c.initializationErr
}

func (c *Config) applyDefaultConfig() error {
	dataHome := c.dataHome
	if dataHome == "" {
		dataHome = xdg.DataHome
	}

	dataDirs := c.dataDirs
	if dataDirs == nil {
		dataDirs = xdg.DataDirs
	}

	root, err := selectXDGTemplateRoot(dataHome, dataDirs)
	if err != nil {
		return err
	}

	rootChanged := filepath.Clean(c.TemplatesDirectory) != filepath.Clean(root)
	c.setTemplatesDir(root)
	if rootChanged {
		c.TemplateVersion = ""
	}

	return nil
}
