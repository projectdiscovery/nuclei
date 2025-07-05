package protocolstate

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	// LfaAllowed means local file access is allowed
	LfaAllowed bool
)

// Normalizepath normalizes path and returns absolute path
// it returns error if path is not allowed
// this respects the sandbox rules and only loads files from
// allowed directories
func NormalizePath(filePath string) (string, error) {
	// TODO: this should be tied to executionID
	if LfaAllowed {
		return filePath, nil
	}
	cleaned, err := fileutil.ResolveNClean(filePath, config.DefaultConfig.GetTemplateDir())
	if err != nil {
		return "", errorutil.NewWithErr(err).Msgf("could not resolve and clean path %v", filePath)
	}
	// only allow files inside nuclei-templates directory
	// even current working directory is not allowed
	if strings.HasPrefix(cleaned, config.DefaultConfig.GetTemplateDir()) {
		return cleaned, nil
	}
	return "", errorutil.New("path %v is outside nuclei-template directory and -lfa is not enabled", filePath)
}
