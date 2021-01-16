package catalogue

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/karrick/godirwalk"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

// GetTemplatesPath returns a list of absolute paths for the provided template list.
func (c *Catalogue) GetTemplatesPath(definitions []string) []string {
	// keeps track of processed dirs and files
	processed := make(map[string]bool)
	allTemplates := []string{}

	for _, t := range definitions {
		paths, err := c.GetTemplatePath(t)
		if err != nil {
			gologger.Error().Msgf("Could not find template '%s': %s\n", t, err)
		}
		for _, path := range paths {
			if _, ok := processed[path]; !ok {
				processed[path] = true
				allTemplates = append(allTemplates, path)
			}
		}
	}
	if len(allTemplates) > 0 {
		gologger.Verbose().Msgf("Identified %d templates", len(allTemplates))
	}
	return allTemplates
}

// GetTemplatePath parses the specified input template path and returns a compiled
// list of finished absolute paths to the templates evaluating any glob patterns
// or folders provided as in.
func (c *Catalogue) GetTemplatePath(target string) ([]string, error) {
	processed := make(map[string]struct{})

	absPath, err := c.convertPathToAbsolute(target)
	if err != nil {
		return nil, errors.Wrapf(err, "could not find template file")
	}

	// Template input includes a wildcard
	if strings.Contains(absPath, "*") {
		matches, err := c.findGlobPathMatches(absPath, processed)
		if err != nil {
			return nil, errors.Wrap(err, "could not find glob matches")
		}
		if len(matches) == 0 {
			return nil, errors.Errorf("no templates found for path")
		}
		return matches, nil
	}

	// Template input is either a file or a directory
	match, file, err := c.findFileMatches(absPath, processed)
	if err != nil {
		return nil, errors.Wrap(err, "could not find file")
	}
	if file {
		if match != "" {
			return []string{match}, nil
		}
		return nil, nil
	}

	// Recursively walk down the Templates directory and run all
	// the template file checks
	matches, err := c.findDirectoryMatches(absPath, processed)
	if err != nil {
		return nil, errors.Wrap(err, "could not find directory matches")
	}
	if len(matches) == 0 {
		return nil, errors.Errorf("no templates found in path")
	}
	return matches, nil
}

// convertPathToAbsolute resolves the paths provided to absolute paths
// before doing any operations on them regardless of them being blob, folders, files, etc.
func (c *Catalogue) convertPathToAbsolute(t string) (string, error) {
	if strings.Contains(t, "*") {
		file := path.Base(t)
		absPath, err := c.ResolvePath(path.Dir(t), "")
		if err != nil {
			return "", err
		}
		return path.Join(absPath, file), nil
	}
	return c.ResolvePath(t, "")
}

// findGlobPathMatches returns the matched files from a glob path
func (c *Catalogue) findGlobPathMatches(absPath string, processed map[string]struct{}) ([]string, error) {
	matches, err := filepath.Glob(absPath)
	if err != nil {
		return nil, errors.Errorf("wildcard found, but unable to glob: %s\n", err)
	}
	results := make([]string, 0, len(matches))
	for _, match := range matches {
		if _, ok := processed[match]; !ok {
			processed[match] = struct{}{}
			results = append(results, match)
		}
	}
	return results, nil
}

// findFileMatches finds if a path is an absolute file. If the path
// is a file, it returns true otherwise false with no errors.
func (c *Catalogue) findFileMatches(absPath string, processed map[string]struct{}) (string, bool, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return "", false, err
	}
	if !info.Mode().IsRegular() {
		return "", false, nil
	}
	if _, ok := processed[absPath]; !ok {
		processed[absPath] = struct{}{}
		return absPath, true, nil
	}
	return "", true, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (c *Catalogue) findDirectoryMatches(absPath string, processed map[string]struct{}) ([]string, error) {
	var results []string
	err := godirwalk.Walk(absPath, &godirwalk.Options{
		Unsorted: true,
		ErrorCallback: func(fsPath string, err error) godirwalk.ErrorAction {
			return godirwalk.SkipNode
		},
		Callback: func(path string, d *godirwalk.Dirent) error {
			if !d.IsDir() && strings.HasSuffix(path, ".yaml") {
				if c.checkIfInNucleiIgnore(path) {
					return nil
				}

				if _, ok := processed[path]; !ok {
					results = append(results, path)
					processed[path] = struct{}{}
				}
			}
			return nil
		},
	})
	return results, err
}
