package catalog

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"

	"github.com/projectdiscovery/folderutil"
)

// ResolvePath resolves the path to an absolute one in various ways.
//
// It checks if the filename is an absolute path, looks in the current directory
// or checking the nuclei templates directory. If a second path is given,
// it also tries to find paths relative to that second path.
func (c *Catalog) ResolvePath(templateName, second string) (string, error) {
	// only perform relative paths or current directory if the scope is not
	// restricted.
	if !c.RestrictScope {
		if filepath.IsAbs(templateName) {
			return templateName, nil
		}
		if second != "" {
			secondBasePath := filepath.Join(filepath.Dir(second), templateName)
			if potentialPath, err := c.tryResolve(secondBasePath); err != errNoValidCombination {
				return potentialPath, nil
			}
		}

		curDirectory, err := os.Getwd()
		if err != nil {
			return "", err
		}

		templatePath := filepath.Join(curDirectory, templateName)
		if potentialPath, err := c.tryResolve(templatePath); err != errNoValidCombination {
			return potentialPath, nil
		}
	}
	if c.templatesDirectory != "" {
		templatePath := filepath.Join(c.templatesDirectory, templateName)
		if potentialPath, err := c.tryResolve(templatePath); err != errNoValidCombination {
			return potentialPath, nil
		}
	}
	return "", fmt.Errorf("no such path found: %s", templateName)
}

var errNoValidCombination = errors.New("no valid combination found")

// tryResolve attempts to load locate the target by iterating across all the folders tree
func (c *Catalog) tryResolve(fullpath string) (string, error) {
	dir, filename := filepath.Split(fullpath)
	pathInfo, err := folderutil.NewPathInfo(dir)
	if err != nil {
		return "", err
	}
	pathInfoItems, err := pathInfo.MeshWith(filename)
	if err != nil {
		return "", err
	}
	for _, pathInfoItem := range pathInfoItems {
		if _, err := os.Stat(pathInfoItem); !os.IsNotExist(err) {
			return pathInfoItem, nil
		}
	}

	return "", errNoValidCombination
}
