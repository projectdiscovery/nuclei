package file

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	fileutil "github.com/projectdiscovery/utils/file"
	folderutil "github.com/projectdiscovery/utils/folder"
)

// getInputPaths parses the specified input paths and returns a compiled
// list of finished absolute paths to the files evaluating any allowlist, denylist,
// glob, file or folders, etc.
func (request *Request) getInputPaths(target string, callback func(string)) error {
	processed := make(map[string]struct{})

	// Template input includes a wildcard
	if strings.Contains(target, "*") && !request.NoRecursive {
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
	if request.NoRecursive {
		return nil // we don't process dirs in no-recursive mode
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
		if !request.validatePath(absPath, match, false) {
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
func (request *Request) findFileMatches(absPath string, processed map[string]struct{}, callback func(string)) (bool, error) {
	info, err := os.Stat(absPath)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, nil
	}
	if _, ok := processed[absPath]; !ok {
		if !request.validatePath(absPath, absPath, false) {
			return false, nil
		}
		processed[absPath] = struct{}{}
		callback(absPath)
	}
	return true, nil
}

// findDirectoryMatches finds matches for templates from a directory
func (request *Request) findDirectoryMatches(absPath string, processed map[string]struct{}, callback func(string)) error {
	err := filepath.WalkDir(
		absPath,
		func(path string, d fs.DirEntry, err error) error {
			// continue on errors
			if err != nil {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if !request.validatePath(absPath, path, false) {
				return nil
			}
			if _, ok := processed[path]; !ok {
				callback(path)
				processed[path] = struct{}{}
			}
			return nil
		},
	)
	return err
}

// validatePath validates a file path for blacklist and whitelist options
func (request *Request) validatePath(absPath, item string, inArchive bool) bool {
	extension := filepath.Ext(item)
	// extension check
	if len(request.extensions) > 0 {
		if _, ok := request.extensions[extension]; ok {
			return true
		} else if !request.allExtensions {
			return false
		}
	}

	var (
		fileExists bool
		dataChunk  []byte
	)
	if !inArchive && request.MimeType {
		// mime type check
		// read first bytes to infer runtime type
		fileExists = fileutil.FileExists(item)
		if fileExists {
			dataChunk, _ = readChunk(item)
			if len(request.mimeTypesChecks) > 0 && matchAnyMimeTypes(dataChunk, request.mimeTypesChecks) {
				return true
			}
		}
	}

	if matchingRule, ok := request.isInDenyList(absPath, item); ok {
		gologger.Verbose().Msgf("Ignoring path %s due to denylist item %s\n", item, matchingRule)
		return false
	}

	// denied mime type checks
	if !inArchive && request.MimeType && fileExists {
		if len(request.denyMimeTypesChecks) > 0 && matchAnyMimeTypes(dataChunk, request.denyMimeTypesChecks) {
			return false
		}
	}

	return true
}

func (request *Request) isInDenyList(absPath, item string) (string, bool) {
	extension := filepath.Ext(item)
	// check for possible deny rules
	// - extension is in deny list
	if _, ok := request.denyList[extension]; ok {
		return extension, true
	}

	// - full path is in deny list
	if _, ok := request.denyList[item]; ok {
		return item, true
	}

	// file is in a forbidden subdirectory
	filename := filepath.Base(item)
	fullPathWithoutFilename := strings.TrimSuffix(item, filename)
	relativePathWithFilename := strings.TrimPrefix(item, absPath)
	relativePath := strings.TrimSuffix(relativePathWithFilename, filename)

	// - filename is in deny list
	if _, ok := request.denyList[filename]; ok {
		return filename, true
	}

	// - relative path is in deny list
	if _, ok := request.denyList[relativePath]; ok {
		return relativePath, true
	}

	// relative path + filename are in the forbidden list
	if _, ok := request.denyList[relativePathWithFilename]; ok {
		return relativePathWithFilename, true
	}

	// root path + relative path are in the forbidden list
	if _, ok := request.denyList[fullPathWithoutFilename]; ok {
		return fullPathWithoutFilename, true
	}

	// check any progressive combined part of the relative and absolute path with filename for matches within rules prefixes
	if pathTreeItem, ok := request.isAnyChunkInDenyList(relativePath, false); ok {
		return pathTreeItem, true
	}
	if pathTreeItem, ok := request.isAnyChunkInDenyList(item, true); ok {
		return pathTreeItem, true
	}

	return "", false
}

func readChunk(fileName string) ([]byte, error) {
	r, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	defer r.Close()

	var buff [1024]byte
	if _, err = io.ReadFull(r, buff[:]); err != nil {
		return nil, err
	}
	return buff[:], nil
}

func (request *Request) isAnyChunkInDenyList(path string, splitWithUtils bool) (string, bool) {
	var paths []string

	if splitWithUtils {
		pathInfo, _ := folderutil.NewPathInfo(path)
		paths, _ = pathInfo.Paths()
	} else {
		pathTree := strings.Split(path, string(os.PathSeparator))
		for i := range pathTree {
			paths = append(paths, filepath.Join(pathTree[:i]...))
		}
	}
	for _, pathTreeItem := range paths {
		if _, ok := request.denyList[pathTreeItem]; ok {
			return pathTreeItem, true
		}
	}

	return "", false
}
