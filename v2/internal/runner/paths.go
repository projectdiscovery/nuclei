package runner

import (
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/projectdiscovery/gologger"
)

// isRelative checks if a given path is a relative path
func isRelative(filePath string) bool {
	if strings.HasPrefix(filePath, "/") || strings.Contains(filePath, ":\\") {
		return false
	}

	return true
}

// resolvePath gets the absolute path to the template by either
// looking in the current directory or checking the nuclei templates directory.
//
// Current directory is given preference over the nuclei-templates directory.
func (r *Runner) resolvePath(templateName string) (string, error) {
	curDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}

	templatePath := path.Join(curDirectory, templateName)
	if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
		gologger.Debugf("Found template in current directory: %s\n", templatePath)

		return templatePath, nil
	}

	if r.templatesConfig != nil {
		templatePath := path.Join(r.templatesConfig.TemplatesDirectory, templateName)
		if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
			gologger.Debugf("Found template in nuclei-templates directory: %s\n", templatePath)

			return templatePath, nil
		}
	}

	return "", fmt.Errorf("no such path found: %s", templateName)
}
