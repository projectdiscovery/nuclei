package runner

import (
	"bufio"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
)

// nucleiConfig contains some configuration options for nuclei
type nucleiConfig struct {
	TemplatesDirectory string    `json:"templates-directory,omitempty"`
	CurrentVersion     string    `json:"current-version,omitempty"`
	LastChecked        time.Time `json:"last-checked,omitempty"`

	// IgnorePaths ignores all the paths listed unless specified manually
	IgnorePaths []string `json:"ignore-paths,omitempty"`
}

// nucleiConfigFilename is the filename of nuclei configuration file.
const nucleiConfigFilename = ".nuclei-config.json"

var reVersion = regexp.MustCompile(`\d+\.\d+\.\d+`)

// readConfiguration reads the nuclei configuration file from disk.
func readConfiguration() (*nucleiConfig, error) {
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

const nucleiIgnoreFile = ".nuclei-ignore"

// readNucleiIgnoreFile reads the nuclei ignore file marking it in map
func (r *Runner) readNucleiIgnoreFile() {
	file, err := os.Open(r.getIgnoreFilePath())
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "#") {
			continue
		}
		r.templatesConfig.IgnorePaths = append(r.templatesConfig.IgnorePaths, text)
	}
}

// getIgnoreFilePath returns the ignore file path for the runner
func (r *Runner) getIgnoreFilePath() string {
	defIgnoreFilePath := path.Join(r.templatesConfig.TemplatesDirectory, nucleiIgnoreFile)

	cwd, err := os.Getwd()
	if err != nil {
		return defIgnoreFilePath
	}
	cwdIgnoreFilePath := path.Join(cwd, nucleiIgnoreFile)

	cwdIfpInfo, err := os.Stat(cwdIgnoreFilePath)
	if os.IsNotExist(err) || cwdIfpInfo.IsDir() {
		return defIgnoreFilePath
	}
	return cwdIgnoreFilePath
}
