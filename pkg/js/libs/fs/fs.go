package fs

import (
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// ListDir lists all files and directories within a path
// depending on the itemType provided
// itemType can be any one of ['file','dir','all']
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

// ReadFilesFromDir reads all files from a directory
// and returns a array with file contents of all files
func ReadFilesFromDir(dir string) ([]string, error) {
	files, err := ListDir(dir, "file")
	if err != nil {
		return nil, err
	}
	var results []string
	for _, file := range files {
		content, err := ReadFileAsString(dir + "/" + file)
		if err != nil {
			return nil, err
		}
		results = append(results, content)
	}
	return results, nil
}
