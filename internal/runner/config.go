package runner

import (
	"os"
	"path"
	"regexp"
	"time"

	jsoniter "github.com/json-iterator/go"
)

// nucleiConfig contains some configuration options for nuclei
type nucleiConfig struct {
	TemplatesDirectory string    `json:"templates-directory,omitempty"`
	CurrentVersion     string    `json:"current-version,omitempty"`
	LastChecked        time.Time `json:"last-checked,omitempty"`
}

// nucleiConfigFilename is the filename of nuclei configuration file.
const nucleiConfigFilename = ".nuclei-config.json"

var reVersion = regexp.MustCompile(`\d+\.\d+\.\d+`)

// readConfiguration reads the nuclei configuration file from disk.
func (r *Runner) readConfiguration() (*nucleiConfig, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	templatesConfigFile := path.Join(home, nucleiConfigFilename)
	file, err := os.Open(templatesConfigFile)

	if err != nil {
		return nil, err
	}

	defer file.Close()

	config := &nucleiConfig{}
	err = jsoniter.NewDecoder(file).Decode(config)

	if err != nil {
		return nil, err
	}

	return config, nil
}

// readConfiguration reads the nuclei configuration file from disk.
func (r *Runner) writeConfiguration(config *nucleiConfig) error {
	home, err := os.UserHomeDir()

	if err != nil {
		return err
	}

	config.LastChecked = time.Now()
	templatesConfigFile := path.Join(home, nucleiConfigFilename)
	file, err := os.OpenFile(templatesConfigFile, os.O_WRONLY|os.O_CREATE, 0777)

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
