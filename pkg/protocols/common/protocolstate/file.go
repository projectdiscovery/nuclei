package protocolstate

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
)

var (
	// LfaAllowed means local file access is allowed
	LfaAllowed bool
	lfaMutex   sync.Mutex
)

// IsLfaAllowed returns whether local file access is allowed
func IsLfaAllowed(options *types.Options) bool {
	// Use the global when no options are provided
	if options == nil {
		lfaMutex.Lock()
		defer lfaMutex.Unlock()
		return LfaAllowed
	}
	// Otherwise the specific options
	dialers, ok := dialers.Get(options.ExecutionId)
	if ok && dialers != nil {
		dialers.Lock()
		defer dialers.Unlock()

		return dialers.LocalFileAccessAllowed
	}
	return false
}

func SetLfaAllowed(options *types.Options) {
	// TODO: Replace this global with per-options function calls. The big lift is handling the javascript fs module callbacks.
	lfaMutex.Lock()
	if options != nil {
		LfaAllowed = options.AllowLocalFileAccess
	}
	lfaMutex.Unlock()
}

func GetLfaAllowed(options *types.Options) bool {
	if options != nil {
		return options.AllowLocalFileAccess
	}
	// TODO: Replace this global with per-options function calls. The big lift is handling the javascript fs module callbacks.
	lfaMutex.Lock()
	defer lfaMutex.Unlock()
	return LfaAllowed
}

// Normalizepath normalizes path and returns absolute path
// it returns error if path is not allowed
// this respects the sandbox rules and only loads files from
// allowed directories
func NormalizePath(filePath string) (string, error) {
	// TODO: this should be tied to executionID using *types.Options
	if IsLfaAllowed(nil) {
		// if local file access is allowed, we can return the absolute path
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
