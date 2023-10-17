package offlinehttp

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// getInputPaths parses the specified input paths and returns a compiled
// list of finished absolute paths to the files evaluating any allowlist, denylist,
// glob, file or folders, etc.
func (request *Request) getInputPaths(target string, callback func(string)) error {
	processed := make(map[string]struct{})

	// Template input includes a wildcard
	if strings.Contains(target, "*") {
		if err := request.findGlobPathMatches(target, processed, callback); err != nil {
			return errors.Wrap(err, "could not find glob matches")
		}
		return nil
	}

	// Template input is either a file or a directory
	file, err := request.findFileMatches(target, processed, callback)
	if err != nil {
		return errors.Wrap(err, "could not find file")
	}
	if file {
		return nil
	}

	// Recursively walk down the Templates directory and run all
	// the template file checks
	if err := request.findDirectoryMatches(target, processed, callback); err != nil {
		return errors.Wrap(err, "could not find directory matches")
	}
	return nil
}

// findGlobPathMatches returns the matched files from a glob path
func (request *Request) findGlobPathMatches(absPath string, processed map[string]struct{}, callback func(string)) error {
	matches, err := filepath.Glob(absPath)
	if err != nil {
		return errors.Errorf("wildcard found, but unable to glob: %s\n", err)
	}
	for _, match := range matches {
		if filepath.Ext(match) != ".txt" {
			continue // only process .txt files
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
func (request *Request) findFileMatches(absPath string, processed map[string]struct{}, callback func(string)) (bool, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	if filepath.Ext(absPath) != ".txt" {
		return false, nil // only process .txt files
	}
	if _, ok := processed[absPath]; !ok {
		processed[absPath] = struct{}{}
		callback(absPath)
	}
	return true, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (request *Request) findDirectoryMatches(absPath string, processed map[string]struct{}, callback func(string)) error {
	err := filepath.WalkDir(
		absPath,
		func(p string, d fs.DirEntry, err error) error {
			// continue on errors
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(p) != ".txt" {
				return nil // only process .txt files
			}
			if _, ok := processed[p]; !ok {
				callback(p)
				processed[p] = struct{}{}
			}
			return nil
		},
	)
	return err
}
