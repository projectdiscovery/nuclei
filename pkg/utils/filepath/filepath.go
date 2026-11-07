package filepathutil

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// IsPathWithinDirectory returns true when path resolves inside directory.
// Both values are canonicalized to handle symlinks and platform-specific case rules.
//
// An empty path or empty directory always returns false; callers that want to
// anchor on the working directory must pass it explicitly via os.Getwd().
func IsPathWithinDirectory(path string, directory string) bool {
	if path == "" || directory == "" {
		return false
	}

	canonicalPath := canonicalizePath(path)
	canonicalDirectory := canonicalizePath(directory)

	relativePath, err := filepath.Rel(canonicalDirectory, canonicalPath)
	if err != nil {
		return false
	}
	return relativePath == "." || (relativePath != ".." && !strings.HasPrefix(relativePath, ".."+string(filepath.Separator)))
}

// IsPathWithinAnyDirectory returns true when path resolves inside any directory.
func IsPathWithinAnyDirectory(path string, directories ...string) bool {
	for _, directory := range directories {
		if directory == "" {
			continue
		}
		if IsPathWithinDirectory(path, directory) {
			return true
		}
	}
	return false
}

// IsHardLinkedRegularFile reports whether path is a regular file with more than
// one hard link. Symlinks and non-regular files return false, as does the case
// where the link count cannot be determined (e.g. on Windows).
func IsHardLinkedRegularFile(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	if !info.Mode().IsRegular() {
		return false
	}
	n, ok := hardLinkCount(path, info)
	return ok && n > 1
}

func canonicalizePath(path string) string {
	canonicalPath, err := filepath.Abs(path)
	if err != nil {
		canonicalPath = filepath.Clean(path)
	}
	if resolvedPath, err := filepath.EvalSymlinks(canonicalPath); err == nil {
		canonicalPath = resolvedPath
	} else {
		canonicalPath = resolveExistingPathPrefix(canonicalPath)
	}
	canonicalPath = filepath.Clean(canonicalPath)
	if runtime.GOOS == "windows" {
		canonicalPath = strings.ToLower(canonicalPath)
	}
	return canonicalPath
}

func resolveExistingPathPrefix(path string) string {
	cleaned := filepath.Clean(path)
	current := cleaned
	var missing []string

	for {
		resolved, err := filepath.EvalSymlinks(current)
		if err == nil {
			for i := len(missing) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, missing[i])
			}
			return resolved
		}

		parent := filepath.Dir(current)
		if parent == current {
			return cleaned
		}
		missing = append(missing, filepath.Base(current))
		current = parent
	}
}
