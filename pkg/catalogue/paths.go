package catalogue

import (
	"fmt"
	"os"
	"path"
	"strings"
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
func (c *Catalogue) resolvePath(templateName string) (string, error) {
	curDirectory, err := os.Getwd()
	if err != nil {
		return "", err
	}

	templatePath := path.Join(curDirectory, templateName)
	if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
		return templatePath, nil
	}

	if c.templatesDirectory != "" {
		templatePath := path.Join(c.templatesDirectory, templateName)
		if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
			return templatePath, nil
		}
	}
	return "", fmt.Errorf("no such path found: %s", templateName)
}

func resolvePathWithBaseFolder(baseFolder, templateName string) (string, error) {
	templatePath := path.Join(baseFolder, templateName)
	if _, err := os.Stat(templatePath); !os.IsNotExist(err) {
		return templatePath, nil
	}
	return "", fmt.Errorf("no such path found: %s", templateName)
}
