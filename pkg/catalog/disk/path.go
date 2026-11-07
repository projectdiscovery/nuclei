package disk

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	fileutil "github.com/projectdiscovery/utils/file"
)

// ResolvePath resolves the path to an absolute one in various ways.
//
// It checks if the filename is an absolute path, looks in the current directory
// or checking the nuclei templates directory. If a second path is given,
// it also tries to find paths relative to that second path.
func (c *DiskCatalog) ResolvePath(templateName, second string) (string, error) {
	if filepath.IsAbs(templateName) {
		return templateName, nil
	}
	if c.templatesFS != nil {
		if potentialPath, err := c.tryResolve(templateName); err != errNoValidCombination {
			return potentialPath, nil
		}
	}
	if second != "" {
		secondBasePath := filepath.Join(filepath.Dir(second), templateName)
		if potentialPath, err := c.tryResolve(secondBasePath); err != errNoValidCombination {
			return potentialPath, nil
		}
	}

	if c.templatesFS == nil {
		curDirectory, err := os.Getwd()
		if err != nil {
			return "", err
		}

		templatePath := filepath.Join(curDirectory, templateName)
		if potentialPath, err := c.tryResolve(templatePath); err != errNoValidCombination {
			return potentialPath, nil
		}
	}

	templatePath := filepath.Join(config.DefaultConfig.GetTemplateDir(), templateName)
	if potentialPath, err := c.tryResolve(templatePath); err != errNoValidCombination {
		return potentialPath, nil
	}

	return "", fmt.Errorf("no such path found: %s", templateName)
}

var errNoValidCombination = errors.New("no valid combination found")

// tryResolve attempts to load locate the target by iterating across all the folders tree
func (c *DiskCatalog) tryResolve(fullPath string) (string, error) {
	if c.templatesFS == nil {
		if fileutil.FileOrFolderExists(fullPath) {
			return fullPath, nil
		}
	} else {
		if _, err := fs.Stat(c.templatesFS, fullPath); err == nil {
			return fullPath, nil
		}
	}
	return "", errNoValidCombination
}
