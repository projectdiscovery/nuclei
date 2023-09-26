package protocolstate

import (
	"path/filepath"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	// lfaAllowed means local file access is allowed
	lfaAllowed bool
)

// Normalizepath normalizes path and returns absolute path
// it returns error if path is not allowed
// this respects the sandbox rules and only loads files from
// allowed directories
func NormalizePath(filePath string) (string, error) {
	filePath = filepath.Clean(filePath)
	templateDirectory := config.DefaultConfig.TemplatesDirectory

	tmpPath := filepath.Join(templateDirectory, filePath)
	var err error
	tmpPath, err = filepath.Abs(tmpPath)
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not get absolute path of %v", tmpPath)
	}
	// first try to resolve this path with 'nuclei-templates' directory as base
	if fileutil.FileOrFolderExists(tmpPath) {
		// this is a valid and allowed path
		return tmpPath, nil
	}
	// for security reasons , access to files outside nuclei-templates directory is not allowed
	// even current working directory is not allowed
	// when lfa is allowed any path is allowed
	if lfaAllowed {
		return filePath, nil
	}
	return "", errorutil.New("path %v is outside nuclei-template directory and -lfa is not enabled", filePath)
}
