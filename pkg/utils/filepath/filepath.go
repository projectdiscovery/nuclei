package filepathutil

import (
	"path/filepath"
	"runtime"
	"strings"
)

// IsPathWithinDirectory returns true when path resolves inside directory.
// Both values are canonicalized to handle symlinks and platform-specific case rules.
func IsPathWithinDirectory(path string, directory string) bool {
	canonicalPath := canonicalizePath(path)
	canonicalDirectory := canonicalizePath(directory)

	relativePath, err := filepath.Rel(canonicalDirectory, canonicalPath)
	if err != nil {
		return false
	}
	return relativePath == "." || (relativePath != ".." && !strings.HasPrefix(relativePath, ".."+string(filepath.Separator)))
}

func canonicalizePath(path string) string {
	canonicalPath, err := filepath.Abs(path)
	if err != nil {
		canonicalPath = filepath.Clean(path)
	}
	if resolvedPath, err := filepath.EvalSymlinks(canonicalPath); err == nil {
		canonicalPath = resolvedPath
	}
	canonicalPath = filepath.Clean(canonicalPath)
	if runtime.GOOS == "windows" {
		canonicalPath = strings.ToLower(canonicalPath)
	}
	return canonicalPath
}
