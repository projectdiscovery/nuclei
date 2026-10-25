package offlinehttp

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
)

// getInputPaths parses the specified input paths and returns a compiled
// list of finished absolute paths to the files evaluating any allowlist, denylist,
// glob, file or folders, etc.
func (request *Request) getInputPaths(ctx context.Context, target string, callback func(string) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	processed := make(map[string]struct{})

	// Template input includes a wildcard
	if strings.Contains(target, "*") {
		if err := request.findGlobPathMatches(ctx, target, processed, callback); err != nil {
			return errors.Wrap(err, "could not find glob matches")
		}
		return nil
	}

	// Template input is either a file or a directory
	file, err := request.findFileMatches(ctx, target, processed, callback)
	if err != nil {
		return errors.Wrap(err, "could not find file")
	}
	if file {
		return nil
	}

	// Recursively walk down the Templates directory and run all
	// the template file checks
	if err := request.findDirectoryMatches(ctx, target, processed, callback); err != nil {
		return errors.Wrap(err, "could not find directory matches")
	}
	return nil
}

// findGlobPathMatches returns the matched files from a glob path
func (request *Request) findGlobPathMatches(ctx context.Context, absPath string, processed map[string]struct{}, callback func(string) error) error {
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
			if err := callInputPath(ctx, callback, match); err != nil {
				return err
			}
		}
	}
	return nil
}

// findFileMatches finds if a path is an absolute file. If the path
// is a file, it returns true otherwise false with no errors.
func (request *Request) findFileMatches(ctx context.Context, absPath string, processed map[string]struct{}, callback func(string) error) (bool, error) {
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
		if err := callInputPath(ctx, callback, absPath); err != nil {
			return true, err
		}
	}
	return true, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (request *Request) findDirectoryMatches(ctx context.Context, absPath string, processed map[string]struct{}, callback func(string) error) error {
	err := filepath.WalkDir(
		absPath,
		func(p string, d fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			// continue on errors
			if walkErr != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if filepath.Ext(p) != ".txt" {
				return nil // only process .txt files
			}
			if _, ok := processed[p]; !ok {
				processed[p] = struct{}{}
				return callInputPath(ctx, callback, p)
			}
			return nil
		},
	)
	return err
}

func callInputPath(ctx context.Context, callback func(string) error, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if callback == nil {
		return nil
	}
	return callback(path)
}
