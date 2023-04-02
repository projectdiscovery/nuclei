package generators

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
)

// validate validates the payloads if any.
func (g *PayloadGenerator) validate(payloads map[string]interface{}, templatePath string) error {
	for name, payload := range payloads {
		switch payloadType := payload.(type) {
		case string:
			// check if it's a multiline string list
			if len(strings.Split(payloadType, "\n")) != 1 {
				return errors.New("invalid number of lines in payload")
			}

			// check if it's a file and try to load it
			if fileutil.FileExists(payloadType) {
				continue
			}

			changed := false

			dir, _ := filepath.Split(templatePath)
			templatePathInfo, _ := folderutil.NewPathInfo(dir)
			payloadPathsToProbe, _ := templatePathInfo.MeshWith(payloadType)

			for _, payloadPath := range payloadPathsToProbe {
				if fileutil.FileExists(payloadPath) {
					payloads[name] = payloadPath
					changed = true
					break
				}
			}
			if !changed {
				return fmt.Errorf("the %s file for payload %s does not exist or does not contain enough elements", payloadType, name)
			}
		case interface{}:
			loadedPayloads := types.ToStringSlice(payloadType)
			if len(loadedPayloads) == 0 {
				return fmt.Errorf("the payload %s does not contain enough elements", name)
			}
		default:
			return fmt.Errorf("the payload %s has invalid type", name)
		}
	}
	return nil
}
