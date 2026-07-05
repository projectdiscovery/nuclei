package protocolstate

import (
	"os"
	"path/filepath"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	filepathutil "github.com/projectdiscovery/nuclei/v3/pkg/utils/filepath"
	fileutil "github.com/projectdiscovery/utils/file"
)

// AllowedFileRoots returns filesystem roots that template execution may access.
// Templates dir is always included. When -lfa is enabled the current working
// directory and any configured AllowedPaths are added as well.
func AllowedFileRoots(options *types.Options) []string {
	roots := make([]string, 0, 6)
	if templateDir := config.DefaultConfig.GetTemplateDir(); templateDir != "" {
		roots = append(roots, canonicalRoot(templateDir))
	}
	if configDir := config.DefaultConfig.GetConfigDir(); configDir != "" {
		roots = append(roots, canonicalRoot(configDir))
	}
	if tempDir := os.TempDir(); tempDir != "" {
		roots = append(roots, canonicalRoot(tempDir))
	}
	if options != nil && options.StoreResponseDir != "" {
		roots = append(roots, canonicalRoot(options.StoreResponseDir))
	}
	if options == nil || !IsLfaAllowed(options) {
		return uniqueRoots(roots)
	}
	if cwd, err := os.Getwd(); err == nil && cwd != "" {
		roots = append(roots, canonicalRoot(cwd))
	}
	if options != nil {
		// Merge the paths passed directly on options with any recorded for this
		// execution id, so execution-id-only callers (that build a bare
		// *types.Options with just ExecutionId) still honour --allowed-paths.
		allowed := append([]string(nil), options.AllowedPaths...)
		allowed = append(allowed, GetAllowedPaths(options.ExecutionId)...)
		for _, allowedPath := range allowed {
			if allowedPath == "" {
				continue
			}
			roots = append(roots, canonicalRoot(allowedPath))
		}
	}
	return uniqueRoots(roots)
}

func canonicalRoot(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return filepath.Clean(resolved)
	}
	return filepath.Clean(abs)
}

func uniqueRoots(roots []string) []string {
	seen := make(map[string]struct{}, len(roots))
	out := make([]string, 0, len(roots))
	for _, root := range roots {
		if root == "" {
			continue
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	return out
}

func isPathAllowed(options *types.Options, cleanedPath string) bool {
	return filepathutil.IsPathWithinAnyDirectory(cleanedPath, AllowedFileRoots(options)...)
}

func resolveAndCleanPath(filePath, baseDir string) (string, error) {
	return fileutil.ResolveNClean(filePath, baseDir)
}
