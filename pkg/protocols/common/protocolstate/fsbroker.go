package protocolstate

import (
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// ReadFileAllowed reads a file after enforcing filesystem allowlist rules.
func ReadFileAllowed(options *types.Options, filePath string) ([]byte, error) {
	finalPath, err := NormalizePath(options, filePath)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(finalPath)
}

// OpenFileAllowed opens a file after enforcing filesystem allowlist rules.
func OpenFileAllowed(options *types.Options, filePath string) (*os.File, error) {
	finalPath, err := NormalizePath(options, filePath)
	if err != nil {
		return nil, err
	}
	return os.Open(finalPath)
}

// WriteFileAllowed writes a file after enforcing filesystem allowlist rules.
func WriteFileAllowed(options *types.Options, filePath string, data []byte, perm os.FileMode) error {
	finalPath, err := NormalizePath(options, filePath)
	if err != nil {
		return err
	}
	return os.WriteFile(finalPath, data, perm)
}
