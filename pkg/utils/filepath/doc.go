// Package filepathutil provides utilities for safe filepath operations,
// particularly for sandboxing file access in template environments.
//
// It includes functions to check if a path is contained within a directory,
// with proper canonicalization to handle symlinks and platform-specific
// path differences (such as case sensitivity on Windows).
//
// TODO(dwisiswant0): This package should be moved to the
// [github.com/projectdiscovery/utils/filepath], but let see how it goes first.
package filepathutil
