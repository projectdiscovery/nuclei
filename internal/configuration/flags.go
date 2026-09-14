package configuration

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/adrg/xdg"
	"github.com/projectdiscovery/goflags"
	catalogconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

// Selection contains the config and profile selected for one invocation.
type Selection struct {
	Config  string
	Profile string
}

// Load applies automatic config files, one selected config file, and one
// selected profile in priority order. Explicit CLI flags retain precedence.
func Load(
	cfg *catalogconfig.Config,
	flagSet *goflags.FlagSet,
	selected *Selection,
	resolveProfile func(string) (string, error),
	args ...string,
) ([]error, error) {
	userConfigFile := cfg.GetFlagsConfigFilePath()
	defaultUserConfigFile := filepath.Join(xdg.ConfigHome, catalogconfig.BinaryName, catalogconfig.CLIConfigFileName)
	automaticFiles := automaticConfigFiles(xdg.ConfigDirs, runtime.GOOS, userConfigFile)

	return loadConfigFiles(userConfigFile, defaultUserConfigFile, automaticFiles, flagSet, selected, resolveProfile, args...)
}

func loadConfigFiles(
	userConfigFile string,
	defaultUserConfigFile string,
	automaticFiles []string,
	flagSet *goflags.FlagSet,
	selected *Selection,
	resolveProfile func(string) (string, error),
	args ...string,
) ([]error, error) {

	var warnings []error
	if err := prepareUserConfigFile(userConfigFile, defaultUserConfigFile); err != nil {
		warnings = append(warnings, err)
	}

	flagSet.SetConfigFilePaths(automaticFiles...)
	if err := flagSet.Parse(args...); err != nil {
		warnings = append(warnings, fmt.Errorf("automatic configuration was ignored: %w", err))
	}

	if err := mergeSelectedFiles(flagSet, selected, resolveProfile); err != nil {
		return warnings, err
	}

	return warnings, nil
}

func mergeSelectedFiles(
	flagSet *goflags.FlagSet,
	selected *Selection,
	resolveProfile func(string) (string, error),
) error {
	configFile := selected.Config
	if configFile != "" {
		if err := flagSet.MergeConfigFile(configFile); err != nil {
			return fmt.Errorf("read config file %q: %w", configFile, err)
		}

		// A selected config may choose a profile, but it cannot redirect its
		// completed config stage.
		selected.Config = configFile
	}

	if selected.Profile == "" {
		return nil
	}

	profileFile, err := resolveProfile(selected.Profile)
	if err != nil {
		return err
	}
	if err := flagSet.MergeConfigFile(profileFile); err != nil {
		return fmt.Errorf("read template profile %q: %w", profileFile, err)
	}

	// A profile cannot redirect either completed file-selection stage.
	selected.Config = configFile
	selected.Profile = profileFile

	return nil
}

func automaticConfigFiles(configDirs []string, goos, userConfigFile string) []string {
	highestFirst := make([]string, 0, len(configDirs)+2)
	highestFirst = append(highestFirst, userConfigFile)

	if unixSystemFile := unixSystemConfigFilePath(goos); unixSystemFile != "" {
		highestFirst = append(highestFirst, unixSystemFile)
	}

	for _, configDir := range configDirs {
		if filepath.IsAbs(configDir) {
			highestFirst = append(highestFirst, filepath.Join(configDir, catalogconfig.BinaryName, catalogconfig.CLIConfigFileName))
		}
	}

	files := make([]string, 0, len(highestFirst))
	seen := make(map[string]struct{}, len(highestFirst))

	for _, file := range highestFirst {
		if file == "" {
			continue
		}

		cleanFile := filepath.Clean(file)
		if _, exists := seen[cleanFile]; exists {
			continue
		}

		seen[cleanFile] = struct{}{}
		files = append(files, file)
	}

	slices.Reverse(files)

	return files
}

func unixSystemConfigFilePath(goos string) string {
	switch goos {
	case "aix", "darwin", "dragonfly", "freebsd", "linux", "netbsd", "openbsd", "solaris":
		return path.Join("/etc", catalogconfig.BinaryName, catalogconfig.CLIConfigFileName)
	default:
		return ""
	}
}

func prepareUserConfigFile(configFile, defaultConfigFile string) error {
	if filepath.Clean(configFile) == filepath.Clean(defaultConfigFile) {
		return nil
	}

	if _, err := os.Stat(configFile); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect custom config file %q: %w", configFile, err)
	}

	data, err := os.ReadFile(defaultConfigFile)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read default config file %q: %w", defaultConfigFile, err)
	}

	if err := os.MkdirAll(filepath.Dir(configFile), 0o700); err != nil {
		return fmt.Errorf("create custom config directory %q: %w", filepath.Dir(configFile), err)
	}

	file, err := os.OpenFile(configFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return nil
	}

	if err != nil {
		return fmt.Errorf("create custom config file %q: %w", configFile, err)
	}

	written := false

	defer func() {
		_ = file.Close()
		if !written {
			_ = os.Remove(configFile)
		}
	}()

	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("copy default config from %q to %q: %w", defaultConfigFile, configFile, err)
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("close custom config file %q: %w", configFile, err)
	}

	written = true

	return nil
}
