package config

import (
	"os"
	"runtime/debug"

	"github.com/projectdiscovery/gologger"
	"gopkg.in/yaml.v2"
)

// IgnoreFile is an internal nuclei template blocking configuration file
type IgnoreFile struct {
	Tags  []string `yaml:"tags"`
	Files []string `yaml:"files"`
}

// ReadIgnoreFile reads the nuclei ignore file returning blocked tags and paths
func ReadIgnoreFile() IgnoreFile {
	file, err := os.Open(DefaultConfig.GetIgnoreFilePath())
	if err != nil {
		if os.IsNotExist(err) {
			gologger.Error().Msgf("Could not read nuclei-ignore file: %s\n", err)
			return IgnoreFile{}
		}
		gologger.Error().Msgf("Could not read nuclei-ignore file: %s\n%s\n", err, string(debug.Stack()))
		return IgnoreFile{}
	}
	defer func() {
		_ = file.Close()
	}()

	ignore := IgnoreFile{}
	if err := yaml.NewDecoder(file).Decode(&ignore); err != nil {
		gologger.Error().Msgf("Could not parse nuclei-ignore file: %s\n", err)
		return IgnoreFile{}
	}
	return ignore
}
