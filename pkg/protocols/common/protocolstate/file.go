package protocolstate

import (
	"errors"
	"fmt"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	filepathutil "github.com/projectdiscovery/nuclei/v3/pkg/utils/filepath"
	"github.com/projectdiscovery/utils/errkit"
	mapsutil "github.com/projectdiscovery/utils/maps"
)

// ErrPathDenied is returned when a path is outside the filesystem allowlist.
var ErrPathDenied = errors.New("path denied by filesystem allowlist")

var (
	// LfaAllowed means local file access is allowed
	LfaAllowed *mapsutil.SyncLockMap[string, bool]
	// allowedPathsByExec stores the -allowed-paths allowlist per execution id so
	// callers that only have an execution id (NormalizePathWithExecutionId,
	// fs.ReadFile, krbforge.normalizeOutputFile) still honour --allowed-paths
	// even though they never see the full *types.Options. A plain guarded map is
	// used because the value is a slice (not comparable, so unusable as a
	// SyncLockMap value).
	allowedPathsMu     sync.RWMutex
	allowedPathsByExec = map[string][]string{}
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
	SetAllowedPaths(options)
}

// SetAllowedPaths records the --allowed-paths allowlist for an execution id so
// execution-id-only path checks can expand the allowlist the same way callers
// that pass full options do.
func SetAllowedPaths(options *types.Options) {
	if options == nil || options.ExecutionId == "" {
		return
	}
	paths := make([]string, 0, len(options.AllowedPaths))
	for _, p := range options.AllowedPaths {
		if p != "" {
			paths = append(paths, p)
		}
	}
	allowedPathsMu.Lock()
	allowedPathsByExec[options.ExecutionId] = paths
	allowedPathsMu.Unlock()
}

// GetAllowedPaths returns the --allowed-paths allowlist recorded for an
// execution id, or nil when none was stored.
func GetAllowedPaths(executionId string) []string {
	if executionId == "" {
		return nil
	}
	allowedPathsMu.RLock()
	defer allowedPathsMu.RUnlock()
	return allowedPathsByExec[executionId]
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
			return "", fmt.Errorf("%w: path %v denied (hard link)", ErrPathDenied, filePath)
		}
		return cleaned, nil
	}
	if options != nil && IsLfaAllowed(options) {
		return "", fmt.Errorf("%w: path %v is outside allowed directories (use --allowed-paths to grant access)", ErrPathDenied, filePath)
	}
	return "", fmt.Errorf("%w: path %v is outside nuclei-template directory and -lfa is not enabled", ErrPathDenied, filePath)
}
