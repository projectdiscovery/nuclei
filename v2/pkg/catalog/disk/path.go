package disk

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	urlutil "github.com/projectdiscovery/utils/url"
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
func (c *DiskCatalog) tryResolve(fullPath string) (string, error) {
	if _, err := os.Stat(fullPath); !os.IsNotExist(err) {
		return fullPath, nil
	}
	return "", errNoValidCombination
}

// BackwardsCompatiblePaths returns new paths for all old/legacy template paths
// Note: this is a temporary function and will be removed in the future release
func BackwardsCompatiblePaths(templateDir string, oldPath string) string {
	// TODO: remove this function in the future release
	// 1. all http related paths are now moved at path /http
	// 2. network related CVES are now moved at path /network/cves
	newPathCallback := func(path string) string {
		// trim prefix slash if any
		path = strings.TrimPrefix(path, "/")
		// try to resolve path at /http subdirectory
		if fileutil.FileOrFolderExists(filepath.Join(templateDir, "http", path)) {
			return filepath.Join(templateDir, "http", path)
			// try to resolve path at /network/cves subdirectory
		} else if strings.HasPrefix(path, "cves") && fileutil.FileOrFolderExists(filepath.Join(templateDir, "network", "cves", path)) {
			return filepath.Join(templateDir, "network", "cves", path)
		}
		// most likely the path is not found
		return filepath.Join(templateDir, path)
	}
	switch {
	case fileutil.FileOrFolderExists(oldPath):
		// new path specified skip processing
		return oldPath
	case filepath.IsAbs(oldPath):
		tmp := strings.TrimPrefix(oldPath, templateDir)
		if tmp == oldPath {
			// user provided absolute path which is not in template directory
			// skip processing
			return oldPath
		}
		// trim the template directory from the path
		return newPathCallback(tmp)
	case strings.Contains(oldPath, urlutil.SchemeSeparator):
		// scheme separator is used to identify the path as url
		// TBD: add support for url directories ??
		return oldPath
	case strings.Contains(oldPath, "*"):
		// this is most likely a glob path skip processing
		return oldPath
	default:
		// this is most likely a relative path
		return newPathCallback(oldPath)
	}
}
