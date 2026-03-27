package main

import (
	"os"
	"path/filepath"
	"runtime"
)

func integrationTestPath(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	if _, err := os.Stat(path); err == nil {
		return path
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return path
	}
	baseDir := filepath.Join(filepath.Dir(currentFile), "..", "..", "integration_tests")
	return filepath.Join(baseDir, filepath.FromSlash(path))
}
