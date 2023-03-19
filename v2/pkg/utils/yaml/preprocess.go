package yaml

import (
	"bytes"
	"errors"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates/extensions"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var reImportsPattern = regexp.MustCompile(`(?m)# !include:(.+.yaml)`)

// StrictSyntax determines if pre-processing directives should be observed
var StrictSyntax bool

// PreProcess all include directives
func PreProcess(data []byte) ([]byte, error) {
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
		if len(match) > 0 {
			includeFileName = string(match[1])
		}

		// gets the number of tabs/spaces between the last \n and the beginning of the match
		matchIndex := bytes.Index(data, matchBytes)
		lastNewLineIndex := bytes.LastIndex(data[:matchIndex], []byte("\n"))
		padBytes := data[lastNewLineIndex:matchIndex]

		// check if the file exists
		if fileutil.FileExists(includeFileName) {
			// and in case replace the comment with it
			includeFileContent, err := os.ReadFile(includeFileName)
			if err != nil {
				return nil, err
			}
			// if it's yaml, tries to preprocess that too recursively
			if stringsutil.HasSuffixAny(includeFileName, extensions.YAML) {
				if subIncludedFileContent, err := PreProcess(includeFileContent); err == nil {
					includeFileContent = subIncludedFileContent
				} else {
					return nil, err
				}
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
