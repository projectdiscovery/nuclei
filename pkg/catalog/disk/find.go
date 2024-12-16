package disk

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	stringsutil "github.com/projectdiscovery/utils/strings"
	updateutils "github.com/projectdiscovery/utils/update"
	urlutil "github.com/projectdiscovery/utils/url"
)

var deprecatedPathsCounter int

// GetTemplatesPath returns a list of absolute paths for the provided template list.
func (c *DiskCatalog) GetTemplatesPath(definitions []string) ([]string, map[string]error) {
	// keeps track of processed dirs and files
	processed := make(map[string]bool)
	allTemplates := []string{}
	erred := make(map[string]error)

	for _, t := range definitions {
		if stringsutil.ContainsAny(t, knownConfigFiles...) {
			// TODO: this is a temporary fix to avoid treating these files as templates
			// this should be replaced with more appropriate and robust logic
			continue
		}
		if strings.Contains(t, urlutil.SchemeSeparator) && stringsutil.ContainsAny(t, config.GetSupportTemplateFileExtensions()...) {
			if _, ok := processed[t]; !ok {
				processed[t] = true
				allTemplates = append(allTemplates, t)
			}
		} else {
			paths, err := c.GetTemplatePath(t)
			if err != nil {
				erred[t] = err
			}
			for _, path := range paths {
				if _, ok := processed[path]; !ok {
					processed[path] = true
					allTemplates = append(allTemplates, path)
				}
			}
		}
	}
	// purge all false positives
	filteredTemplates := []string{}
	for _, v := range allTemplates {
		// TODO: this is a temporary fix to avoid treating these files as templates
		// this should be replaced with more appropriate and robust logic
		if !stringsutil.ContainsAny(v, knownConfigFiles...) {
			filteredTemplates = append(filteredTemplates, v)
		}
	}

	return filteredTemplates, erred
}

// GetTemplatePath parses the specified input template path and returns a compiled
// list of finished absolute paths to the templates evaluating any glob patterns
// or folders provided as in.
func (c *DiskCatalog) GetTemplatePath(target string) ([]string, error) {
	processed := make(map[string]struct{})

	if c.templatesFS == nil {
		var err error
		target, err = c.convertPathToAbsolute(target)
		if err != nil {
			return nil, errors.Wrapf(err, "could not find template file")
		}
	}

	if strings.Contains(target, "*") {
		globMatches, err := c.findGlobPathMatches(target, processed)
		if err != nil {
			return nil, errors.Wrap(err, "could not globbing path")
		}

		if len(globMatches) > 0 {
			return globMatches, nil
		} else {
			return globMatches, fmt.Errorf("%w in path %q", ErrNoTemplatesFound, target)
		}
	}

	// `target` is either a file or a directory
	match, file, err := c.findFileMatches(target, processed)
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
	matches, err := c.findDirectoryMatches(target, processed)
	if err != nil {
		return nil, errors.Wrap(err, "could not find directory matches")
	}

	if len(matches) == 0 {
		return nil, fmt.Errorf("%w in path %q", ErrNoTemplatesFound, target)
	}

	return matches, nil
}

// convertPathToAbsolute resolves the paths provided to absolute paths
// before doing any operations on them regardless of them being BLOB, folders, files, etc.
func (c *DiskCatalog) convertPathToAbsolute(t string) (string, error) {
	if strings.Contains(t, "*") {
		file := filepath.Base(t)
		absPath, err := c.ResolvePath(filepath.Dir(t), "")
		if err != nil {
			return "", err
		}
		return filepath.Join(absPath, file), nil
	}
	return c.ResolvePath(t, "")
}

// findGlobPathMatches returns the matched files from a glob path
func (c *DiskCatalog) findGlobPathMatches(absPath string, processed map[string]struct{}) ([]string, error) {
	// trim templateDir if any
	relPath := strings.TrimPrefix(absPath, c.templatesDirectory)
	// trim leading slash if any
	relPath = strings.TrimPrefix(relPath, string(os.PathSeparator))

	var err error
	var matches []string

	if c.templatesFS != nil {
		matches, err = fs.Glob(c.templatesFS, relPath)
		if err != nil {
			return matches, err
		}
	} else {
		matches, err = filepath.Glob(absPath)
		if err != nil {
			return matches, err
		}
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
func (c *DiskCatalog) findFileMatches(absPath string, processed map[string]struct{}) (match string, matched bool, err error) {
	if c.templatesFS != nil {
		absPath = strings.Trim(absPath, string(filepath.Separator))
	}
	var info fs.File
	if c.templatesFS == nil {
		info, err = os.Open(absPath)
	} else {
		// If we were given no path, then it's not a file, it's the root, and we can quietly return.
		if absPath == "" {
			return "", false, nil
		}

		info, err = c.templatesFS.Open(absPath)
	}
	if err != nil {
		return "", false, err
	}
	stat, err := info.Stat()
	if err != nil {
		return "", false, err
	}
	if !stat.Mode().IsRegular() {
		return "", false, nil
	}
	if _, ok := processed[absPath]; !ok {
		processed[absPath] = struct{}{}
		return absPath, true, nil
	}
	return "", true, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (c *DiskCatalog) findDirectoryMatches(absPath string, processed map[string]struct{}) ([]string, error) {
	var results []string
	var err error
	if c.templatesFS == nil {
		err = filepath.WalkDir(
			absPath,
			func(path string, d fs.DirEntry, err error) error {
				// continue on errors
				if err != nil {
					return nil
				}
				if !d.IsDir() && config.GetTemplateFormatFromExt(path) != config.Unknown {
					if _, ok := processed[path]; !ok {
						results = append(results, path)
						processed[path] = struct{}{}
					}
				}
				return nil
			},
		)
	} else {
		// For the special case of the root directory, we need to pass "." to `fs.WalkDir`.
		if absPath == "" {
			absPath = "."
		}
		absPath = strings.TrimSuffix(absPath, string(filepath.Separator))

		err = fs.WalkDir(
			c.templatesFS,
			absPath,
			func(path string, d fs.DirEntry, err error) error {
				// continue on errors
				if err != nil {
					return nil
				}
				if !d.IsDir() && config.GetTemplateFormatFromExt(path) != config.Unknown {
					if _, ok := processed[path]; !ok {
						results = append(results, path)
						processed[path] = struct{}{}
					}
				}
				return nil
			},
		)
	}
	return results, err
}

// PrintDeprecatedPathsMsgIfApplicable prints a warning message if any
// deprecated paths are found. Unless mode is silent warning message is printed.
//
// Deprecated: No longer used since the official Nuclei Templates repository
// have restructured this a long time ago.
func PrintDeprecatedPathsMsgIfApplicable(isSilent bool) {
	if !updateutils.IsOutdated("v9.4.3", config.DefaultConfig.TemplateVersion) {
		return
	}
	if deprecatedPathsCounter > 0 && !isSilent {
		gologger.Print().Msgf("[%v] Found %v template[s] loaded with deprecated paths, update before v3 for continued support.\n", aurora.Yellow("WRN").String(), deprecatedPathsCounter)
	}
}
