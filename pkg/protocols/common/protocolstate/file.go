package protocolstate

import (
	"fmt"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

var (
	// LfaAllowed means local file access is allowed
	LfaAllowed *mapsutil.SyncLockMap[string, bool]
)

func init() {
	LfaAllowed = mapsutil.NewSyncLockMap[string, bool]()
}

// IsLfaAllowed returns whether local file access is allowed
func IsLfaAllowed(options *types.Options) bool {
	if GetLfaAllowed(options) {
		return true
	}

	// Otherwise look into dialers
	dialers, ok := dialers.Get(options.ExecutionId)
	if ok && dialers != nil {
		dialers.Lock()
		defer dialers.Unlock()

		return dialers.LocalFileAccessAllowed
	}

	// otherwise just return option value
	return options.AllowLocalFileAccess
}

func SetLfaAllowed(options *types.Options) {
	_ = LfaAllowed.Set(options.ExecutionId, options.AllowLocalFileAccess)
}

func GetLfaAllowed(options *types.Options) bool {
	allowed, ok := LfaAllowed.Get(options.ExecutionId)

	return ok && allowed
}

func NormalizePathWithExecutionId(executionId string, filePath string) (string, error) {
	options := &types.Options{
		ExecutionId: executionId,
	}
	return NormalizePath(options, filePath)
}

// Normalizepath normalizes path and returns absolute path
// it returns error if path is not allowed
// this respects the sandbox rules and only loads files from
// allowed directories
func NormalizePath(options *types.Options, filePath string) (string, error) {
	// TODO: this should be tied to executionID using *types.Options
	if IsLfaAllowed(options) {
		// if local file access is allowed, we can return the absolute path
		return filePath, nil
	}
	cleaned, err := fileutil.ResolveNClean(filePath, config.DefaultConfig.GetTemplateDir())
	if err != nil {
		return "", errkit.Wrapf(err, "could not resolve and clean path %v", filePath)
	}
	// only allow files inside nuclei-templates directory
	// even current working directory is not allowed
	if strings.HasPrefix(cleaned, config.DefaultConfig.GetTemplateDir()) {
		return cleaned, nil
	}
	return "", errkit.Newf("path %v is outside nuclei-template directory and -lfa is not enabled", filePath)
}
