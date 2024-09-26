package generators

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
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

			// For historical reasons, "validate" checks to see if the payload file exist.
			// If we're using a custom helper function, then we need to skip any validation beyond just checking the string syntax.
			// Actually attempting to load the file will determine whether or not it exists.
			if g.options.LoadHelperFileFunction != nil {
				return nil
			}

			// check if it's a file and try to load it
			if fileutil.FileExists(payloadType) {
				continue
			}
			// if file already exists in nuclei-templates directory, skip any further checks
			if fileutil.FileExists(filepath.Join(config.DefaultConfig.GetTemplateDir(), payloadType)) {
				continue
			}

			// in below code, we calculate all possible paths from root and try to resolve the payload
			// at each level of the path. if the payload is found, we break the loop and continue
			// ex: template-path: /home/user/nuclei-templates/cves/2020/CVE-2020-1234.yaml
			// then we check if helper file "my-payload.txt" exists at below paths:
			// 1. /home/user/nuclei-templates/cves/2020/my-payload.txt
			// 2. /home/user/nuclei-templates/cves/my-payload.txt
			// 3. /home/user/nuclei-templates/my-payload.txt
			// 4. /home/user/my-payload.txt
			// 5. /home/my-payload.txt
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
