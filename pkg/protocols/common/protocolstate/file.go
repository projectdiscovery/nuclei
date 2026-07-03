package protocolstate

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	filepathutil "github.com/projectdiscovery/nuclei/v3/pkg/utils/filepath"
	"github.com/projectdiscovery/utils/errkit"
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

// NormalizePath normalizes path and returns absolute path.
// It returns an error when the resolved path is outside the computed
// filesystem allowlist. -lfa expands the allowlist but never disables it.
func NormalizePath(options *types.Options, filePath string) (string, error) {
	if filePath == "" {
		return "", errkit.New("empty file path is not allowed")
	}
	baseDir := config.DefaultConfig.GetTemplateDir()
	cleaned, err := resolveAndCleanPath(filePath, baseDir)
	if err != nil {
		return "", errkit.Wrapf(err, "could not resolve and clean path %v", filePath)
	}
	if isPathAllowed(options, cleaned) {
		if filepathutil.IsHardLinkedRegularFile(cleaned) {
			return "", errkit.Newf("path %v denied (hard link)", filePath)
		}
		return cleaned, nil
	}
	if options != nil && IsLfaAllowed(options) {
		return "", errkit.Newf("path %v is outside allowed directories (use --allowed-paths to grant access)", filePath)
	}
	return "", errkit.Newf("path %v is outside nuclei-template directory and -lfa is not enabled", filePath)
}
