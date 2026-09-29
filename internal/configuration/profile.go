package configuration

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	catalogconfig "github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	fileutil "github.com/projectdiscovery/utils/file"
)

// TemplatesDirectory returns the final template directory used while loading
// configuration and resolving profiles.
func TemplatesDirectory(options *types.Options, config *catalogconfig.Config) string {
	if templatesDir, overridden := TemplatesDirectoryOverride(options); overridden {
		return templatesDir
	}

	return config.GetTemplateDir()
}

// TemplatesDirectoryOverride returns an explicit flag/config or environment
// template directory.
func TemplatesDirectoryOverride(options *types.Options) (string, bool) {
	templatesDir := options.NewTemplatesDirectory
	if templatesDir == "" {
		templatesDir = os.Getenv(catalogconfig.NucleiTemplatesDirEnv)
	}

	if templatesDir == "" {
		return "", false
	}

	if absPath, err := filepath.Abs(templatesDir); err == nil {
		return absPath, true
	}

	return templatesDir, true
}

// ResolveProfilePath resolves a profile path or profile ID against the active
// template root.
func ResolveProfilePath(profilePath, templatesDir string) (string, error) {
	defaultProfilesPath := filepath.Join(templatesDir, "profiles")
	if filepath.Ext(profilePath) == "" {
		path, err := findProfilePathByID(profilePath, defaultProfilesPath)
		if err != nil {
			return "", err
		}

		if path == "" {
			return "", fmt.Errorf("%q is not a profile ID or profile path", profilePath)
		}

		profilePath = path
	}

	if !filepath.IsAbs(profilePath) {
		if filepath.Dir(profilePath) == "profiles" {
			defaultProfilesPath = templatesDir
		}

		currentDir, err := os.Getwd()
		if err == nil && fileutil.FileExists(filepath.Join(currentDir, profilePath)) {
			profilePath = filepath.Join(currentDir, profilePath)
		} else {
			profilePath = filepath.Join(defaultProfilesPath, profilePath)
		}
	}

	if !fileutil.FileExists(profilePath) {
		return "", fmt.Errorf("given template profile file %q does not exist", profilePath)
	}

	return profilePath, nil
}

func findProfilePathByID(profileID, profilesDir string) (string, error) {
	var profilePath string
	err := filepath.WalkDir(profilesDir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			return nil
		}

		ext := filepath.Ext(path)
		if ext != extensions.YAML && ext != extensions.YML {
			return nil
		}

		if strings.TrimSuffix(filepath.Base(path), ext) == profileID {
			profilePath = path
			return fs.SkipAll
		}

		return nil
	})

	if err != nil {
		return "", fmt.Errorf("search profile ID %q in %q: %w", profileID, profilesDir, err)
	}

	return profilePath, nil
}

// ApplyProfile processes profile-only inline targets and secrets after its
// flag values have been merged. It returns the private directory that owns a
// generated inline-secrets file.
func ApplyProfile(profilePath string, options *types.Options) (string, error) {
	if profilePath == "" {
		return "", nil
	}

	options.Targets = appendInlineTargets(options.Targets, options.InlineTargetsList)
	if strings.Contains(options.TargetsFilePath, "\n") {
		options.Targets = appendInlineTargets(options.Targets, options.TargetsFilePath)
		options.TargetsFilePath = ""
	}

	return processInlineSecretsFromProfile(profilePath, options)
}

func appendInlineTargets(targets []string, input string) []string {
	for target := range strings.SplitSeq(strings.TrimSpace(input), "\n") {
		target = strings.TrimSpace(target)
		if target != "" && !strings.HasPrefix(target, "#") {
			targets = append(targets, target)
		}
	}

	return targets
}

type profileSecrets struct {
	Secrets any `yaml:"secrets"`
}

func processInlineSecretsFromProfile(profilePath string, options *types.Options) (string, error) {
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return "", fmt.Errorf("read profile file %q: %w", profilePath, err)
	}

	var profile profileSecrets
	if err := yaml.Unmarshal(data, &profile); err != nil {
		return "", fmt.Errorf("parse profile YAML %q: %w", profilePath, err)
	}

	if profile.Secrets == nil {
		return "", nil
	}

	secretsData, err := yaml.Marshal(profile.Secrets)
	if err != nil {
		return "", fmt.Errorf("marshal inline profile secrets: %w", err)
	}

	tempDir, err := os.MkdirTemp("", "nuclei-secrets-*")
	if err != nil {
		return "", fmt.Errorf("create inline secrets directory: %w", err)
	}

	removeDir := true
	defer func() {
		if removeDir {
			_ = os.RemoveAll(tempDir)
		}
	}()

	tempPath := filepath.Join(tempDir, "inline-secrets.yaml")
	if err := os.WriteFile(tempPath, secretsData, 0o600); err != nil {
		return "", fmt.Errorf("write inline secrets file %q: %w", tempPath, err)
	}

	removeDir = false
	options.SecretsFile = append(options.SecretsFile, tempPath)

	return tempDir, nil
}
