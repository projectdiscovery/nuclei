package yaml

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var reImportsPattern = regexp.MustCompile(`(?m)# !include:(.+.yaml)`)

const maxIncludeDepth = 32

// StrictSyntax determines if pre-processing directives should be observed
var StrictSyntax bool

// PreProcess all include directives
func PreProcess(data []byte) ([]byte, error) {
	return preProcess(data, make(map[string]struct{}), 0)
}

func preProcess(data []byte, includeStack map[string]struct{}, depth int) ([]byte, error) {
	// find all matches like !include:path\n
	importMatches := reImportsPattern.FindAllSubmatch(data, -1)
	hasImportDirectives := len(importMatches) > 0

	if hasImportDirectives && StrictSyntax {
		return data, errors.New("include directive preprocessing is disabled")
	}

	var replaceItems []string

	for _, match := range importMatches {
		var (
			matchString     string
			includeFileName string
		)
		matchBytes := match[0]
		matchString = string(matchBytes)
		if len(match) > 1 {
			includeFileName = string(match[1])
		}

		// Preserve the newline and indentation that should prefix included content lines.
		matchIndex := bytes.Index(data, matchBytes)
		lastNewLineIndex := bytes.LastIndex(data[:matchIndex], []byte("\n"))
		var padBytes []byte
		if lastNewLineIndex < 0 {
			padBytes = append([]byte("\n"), data[:matchIndex]...)
		} else {
			padBytes = data[lastNewLineIndex:matchIndex]
		}

		// check if the file exists
		if fileutil.FileExists(includeFileName) {
			// and in case replace the comment with it
			includeFileContent, err := readIncludedFile(includeFileName, includeStack, depth)
			if err != nil {
				return nil, err
			}

			// pad each line of file content with padBytes
			includeFileContent = bytes.ReplaceAll(includeFileContent, []byte("\n"), padBytes)

			replaceItems = append(replaceItems, matchString)
			replaceItems = append(replaceItems, string(includeFileContent))
		}
	}

	replacer := strings.NewReplacer(replaceItems...)

	return []byte(replacer.Replace(string(data))), nil
}

func readIncludedFile(includeFileName string, includeStack map[string]struct{}, depth int) ([]byte, error) {
	includePath := includePathKey(includeFileName)
	if _, ok := includeStack[includePath]; ok {
		return nil, fmt.Errorf("circular include directive detected: %s", includeFileName)
	}

	includeStack[includePath] = struct{}{}
	defer delete(includeStack, includePath)

	includeFileContent, err := os.ReadFile(includeFileName)
	if err != nil {
		return nil, err
	}

	// if it's yaml, tries to preprocess that too recursively
	if stringsutil.HasSuffixAny(includeFileName, extensions.YAML) {
		if depth >= maxIncludeDepth {
			return nil, fmt.Errorf("include directive exceeded maximum include depth of %d", maxIncludeDepth)
		}
		includeFileContent, err = preProcess(includeFileContent, includeStack, depth+1)
		if err != nil {
			return nil, err
		}
	}

	return includeFileContent, nil
}

func includePathKey(includeFileName string) string {
	includePath, err := filepath.Abs(includeFileName)
	if err != nil {
		return filepath.Clean(includeFileName)
	}
	if evaluatedPath, err := filepath.EvalSymlinks(includePath); err == nil {
		return evaluatedPath
	}
	return includePath
}
