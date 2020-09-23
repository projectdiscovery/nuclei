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

const nucleiIgnoreFile = ".nuclei-ignore"

// readNucleiIgnoreFile reads the nuclei ignore file marking it in map
func (r *Runner) readNucleiIgnoreFile() {
	file, err := os.Open(path.Join(r.templatesConfig.TemplatesDirectory, nucleiIgnoreFile))
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

		r.templatesConfig.IgnorePaths = append(r.templatesConfig.IgnorePaths, text)
	}
}

// checkIfInNucleiIgnore checks if a path falls under nuclei-ignore rules.
func (r *Runner) checkIfInNucleiIgnore(item string) bool {
	if r.templatesConfig == nil {
		return false
	}

	for _, paths := range r.templatesConfig.IgnorePaths {
		// If we have a path to ignore, check if it's in the item.
		if paths[len(paths)-1] == '/' {
			if strings.Contains(item, paths) {
				return true
			}

			continue
		}
		// Check for file based extension in ignores
		if strings.HasSuffix(item, paths) {
			return true
		}
	}

	return false
}
