package fs

import (
	"os"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// ListDir lists itemType values within a directory
// depending on the itemType provided
// itemType can be any one of ['file','dir',”]
// @example
// ```javascript
// const fs = require('nuclei/fs');
// // this will only return files in /tmp directory
// const files = fs.ListDir('/tmp', 'file');
// ```
// @example
// ```javascript
// const fs = require('nuclei/fs');
// // this will only return directories in /tmp directory
// const dirs = fs.ListDir('/tmp', 'dir');
// ```
// @example
// ```javascript
// const fs = require('nuclei/fs');
// // when no itemType is provided, it will return both files and directories
// const items = fs.ListDir('/tmp');
// ```
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
// and returns content as byte array
// @example
// ```javascript
// const fs = require('nuclei/fs');
// // here permitted directories are $HOME/nuclei-templates/*
// const content = fs.ReadFile('helpers/usernames.txt');
// ```
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
// @example
// ```javascript
// const fs = require('nuclei/fs');
// // here permitted directories are $HOME/nuclei-templates/*
// const content = fs.ReadFileAsString('helpers/usernames.txt');
// ```
func ReadFileAsString(path string) (string, error) {
	bin, err := ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(bin), nil
}

// ReadFilesFromDir reads all files from a directory
// and returns a string array with file contents of all files
// @example
// ```javascript
// const fs = require('nuclei/fs');
// // here permitted directories are $HOME/nuclei-templates/*
// const contents = fs.ReadFilesFromDir('helpers/ssh-keys');
// log(contents);
// ```
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
