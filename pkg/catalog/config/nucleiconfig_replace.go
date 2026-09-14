//go:build !windows

package config

import "os"

func replaceTemplatesConfigFile(temporaryPath, configFilePath string) error {
	return os.Rename(temporaryPath, configFilePath)
}
