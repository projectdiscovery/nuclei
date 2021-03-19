package generators

import (
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
)

// validate validates the payloads if any.
func (g *Generator) validate(payloads map[string]interface{}, templatePath string) error {
	for name, payload := range payloads {
		switch pt := payload.(type) {
		case string:
			// check if it's a multiline string list
			if len(strings.Split(pt, "\n")) != 1 {
				return errors.New("invalid number of lines in payload")
			}

			// check if it's a worldlist file and try to load it
			if fileExists(pt) {
				continue
			}

			changed := false
			pathTokens := strings.Split(templatePath, "/")

			for i := range pathTokens {
				tpath := path.Join(strings.Join(pathTokens[:i], "/"), pt)
				if fileExists(tpath) {
					payloads[name] = tpath
					changed = true
					break
				}
			}
			if !changed {
				return fmt.Errorf("the %s file for payload %s does not exist or does not contain enough elements", pt, name)
			}
		case interface{}:
			loadedPayloads := types.ToStringSlice(pt)
			if len(loadedPayloads) == 0 {
				return fmt.Errorf("the payload %s does not contain enough elements", name)
			}
		default:
			return fmt.Errorf("the payload %s has invalid type", name)
		}
	}
	return nil
}

// fileExists checks if a file exists and is not a directory
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	if info == nil {
		return false
	}
	return !info.IsDir()
}
