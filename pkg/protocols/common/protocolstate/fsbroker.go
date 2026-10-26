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
