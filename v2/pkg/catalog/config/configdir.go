package config

import (
	"path/filepath"

	fileutil "github.com/projectdiscovery/utils/file"
)

// globalConfigDir is the global config directory for nuclei
var globalConfigDir string

// Override the default config directory
func SetCustomConfigDirectory(dir string) {
	globalConfigDir = dir
	if !fileutil.FolderExists(dir) {
		_ = fileutil.CreateFolder(dir)
	}
}

// GetConfigDir returns the nuclei configuration directory
func GetConfigDir() string {
	return globalConfigDir
}

// getTemplateConfigFilePath returns configDir/.templates-config.json file path
func getTemplateConfigFilePath() (string, error) {
	templatesConfigFile := filepath.Join(globalConfigDir, ".templates-config.json")
	return templatesConfigFile, nil
}

func init() {

}
