package config

import (
	"os"
	"path/filepath"
	"strings"
)

// CanonicalTemplatesPath is the identity of a templates directory. A symlink
// and its target are the same directory, including while the target does not
// exist yet, so a lock and a reloaded version follow either name.
func CanonicalTemplatesPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return resolveTemplatesPath(path, map[string]struct{}{})
}

func resolveTemplatesPath(path string, seen map[string]struct{}) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		abs = filepath.Clean(path)
	}
	if _, ok := seen[abs]; ok {
		return abs
	}
	seen[abs] = struct{}{}

	dir := abs
	var missing []string
	for {
		info, err := os.Lstat(dir)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 {
				if resolved, err := filepath.EvalSymlinks(dir); err == nil {
					return filepath.Join(append([]string{resolved}, missing...)...)
				}
				target, readErr := os.Readlink(dir)
				if readErr != nil {
					return filepath.Join(append([]string{dir}, missing...)...)
				}
				if !filepath.IsAbs(target) {
					target = filepath.Join(filepath.Dir(dir), target)
				}
				resolvedTarget := resolveTemplatesPath(target, seen)
				return filepath.Join(append([]string{resolvedTarget}, missing...)...)
			}
			resolved := dir
			if r, err := filepath.EvalSymlinks(dir); err == nil {
				resolved = r
			}
			return filepath.Join(append([]string{resolved}, missing...)...)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return filepath.Join(append([]string{dir}, missing...)...)
		}
		missing = append([]string{filepath.Base(dir)}, missing...)
		dir = parent
	}
}
