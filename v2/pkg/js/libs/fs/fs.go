package fs

import (
	"os"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
)

// ListDir lists directory contents within permitted paths
// itemType can be used to filter type of results
// allowed values are: file, dir, all
func ListDir(path string, itemType string) ([]string, error) {
	finalPath, err := protocolstate.NormalizePath(path)
	if err != nil {
		return nil, err
	}
	values, err := os.ReadDir(finalPath)
	if err != nil {
		return nil, err
	}
	var results []string
	for _, value := range values {
		if itemType == "file" && value.IsDir() {
			continue
		}
		if itemType == "dir" && !value.IsDir() {
			continue
		}
		results = append(results, value.Name())
	}
	return results, nil
}

// ReadFile reads file contents within permitted paths
func ReadFile(path string) ([]byte, error) {
	finalPath, err := protocolstate.NormalizePath(path)
	if err != nil {
		return nil, err
	}
	bin, err := os.ReadFile(finalPath)
	return bin, err
}

// ReadFileAsString reads file contents within permitted paths
// and returns content as string
func ReadFileAsString(path string) (string, error) {
	bin, err := ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(bin), nil
}
