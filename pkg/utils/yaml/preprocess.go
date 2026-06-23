package yaml

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

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
	// FindAllSubmatchIndex is used (instead of FindAllSubmatch) so each match
	// carries its own offset; relying on bytes.Index would always resolve to the
	// first occurrence and incorrectly pad repeated include directives.
	importMatches := reImportsPattern.FindAllSubmatchIndex(data, -1)
	hasImportDirectives := len(importMatches) > 0

	if hasImportDirectives && StrictSyntax {
		return data, errors.New("include directive preprocessing is disabled")
	}

	if !hasImportDirectives {
		return data, nil
	}

	// Expand each directive in place using its own offset. A strings.Replacer
	// cannot be used here because it collapses identical directive lines onto a
	// single replacement, which would reuse the first occurrence's indentation
	// for every later occurrence.
	var out bytes.Buffer
	lastEnd := 0

	for _, match := range importMatches {
		matchStart, matchEnd := match[0], match[1]

		var includeFileName string
		if len(match) > 3 && match[2] >= 0 {
			includeFileName = string(data[match[2]:match[3]])
		}

		// check if the file exists; otherwise leave the directive untouched
		if !fileutil.FileExists(includeFileName) {
			continue
		}

		includeFileContent, err := readIncludedFile(includeFileName, includeStack, depth)
		if err != nil {
			return nil, err
		}

		// Preserve the newline and indentation that should prefix included content lines.
		lastNewLineIndex := bytes.LastIndex(data[:matchStart], []byte("\n"))
		var padBytes []byte
		if lastNewLineIndex < 0 {
			padBytes = append([]byte("\n"), data[:matchStart]...)
		} else {
			padBytes = data[lastNewLineIndex:matchStart]
		}

		// pad each line of file content with padBytes
		includeFileContent = bytes.ReplaceAll(includeFileContent, []byte("\n"), padBytes)

		// copy everything up to the directive (including its indentation), then
		// the expanded content, and resume after the directive.
		out.Write(data[lastEnd:matchStart])
		out.Write(includeFileContent)
		lastEnd = matchEnd
	}
	out.Write(data[lastEnd:])

	return out.Bytes(), nil
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
