package file

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/karrick/godirwalk"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
)

// getInputPaths parses the specified input paths and returns a compiled
// list of finished absolute paths to the files evaluating any allowlist, denylist,
// glob, file or folders, etc.
func (r *Request) getInputPaths(target string, callback func(string)) error {
	processed := make(map[string]struct{})

	// Template input includes a wildcard
	if strings.Contains(target, "*") && !r.NoRecursive {
		if err := r.findGlobPathMatches(target, processed, callback); err != nil {
			return errors.Wrap(err, "could not find glob matches")
		}
		return nil
	}

	// Template input is either a file or a directory
	file, err := r.findFileMatches(target, processed, callback)
	if err != nil {
		return errors.Wrap(err, "could not find file")
	}
	if file {
		return nil
	}
	if r.NoRecursive {
		return nil // we don't process dirs in no-recursive mode
	}
	// Recursively walk down the Templates directory and run all
	// the template file checks
	if err := r.findDirectoryMatches(target, processed, callback); err != nil {
		return errors.Wrap(err, "could not find directory matches")
	}
	return nil
}

// findGlobPathMatches returns the matched files from a glob path
func (r *Request) findGlobPathMatches(absPath string, processed map[string]struct{}, callback func(string)) error {
	matches, err := filepath.Glob(absPath)
	if err != nil {
		return errors.Errorf("wildcard found, but unable to glob: %s\n", err)
	}
	for _, match := range matches {
		if !r.validatePath(match) {
			continue
		}
		if _, ok := processed[match]; !ok {
			processed[match] = struct{}{}
			callback(match)
		}
	}
	return nil
}

// findFileMatches finds if a path is an absolute file. If the path
// is a file, it returns true otherwise false with no errors.
func (r *Request) findFileMatches(absPath string, processed map[string]struct{}, callback func(string)) (bool, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	if _, ok := processed[absPath]; !ok {
		if !r.validatePath(absPath) {
			return false, nil
		}
		processed[absPath] = struct{}{}
		callback(absPath)
	}
	return true, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (r *Request) findDirectoryMatches(absPath string, processed map[string]struct{}, callback func(string)) error {
	err := godirwalk.Walk(absPath, &godirwalk.Options{
		Unsorted: true,
		ErrorCallback: func(fsPath string, err error) godirwalk.ErrorAction {
			return godirwalk.SkipNode
		},
		Callback: func(path string, d *godirwalk.Dirent) error {
			if d.IsDir() {
				return nil
			}
			if !r.validatePath(path) {
				return nil
			}
			if _, ok := processed[path]; !ok {
				callback(path)
				processed[path] = struct{}{}
			}
			return nil
		},
	})
	return err
}

// validatePath validates a file path for blacklist and whitelist options
func (r *Request) validatePath(item string) bool {
	extension := filepath.Ext(item)

	if len(r.extensions) > 0 {
		if _, ok := r.extensions[extension]; ok {
			return true
		} else if !r.allExtensions {
			return false
		}
	}
	if _, ok := r.extensionDenylist[extension]; ok {
		gologger.Verbose().Msgf("Ignoring path %s due to denylist item %s\n", item, extension)
		return false
	}
	return true
}
