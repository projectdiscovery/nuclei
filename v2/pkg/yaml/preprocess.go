package yaml

import (
	"bytes"
	"os"
	"regexp"
	"strings"

	"github.com/projectdiscovery/fileutil"
)

var regexImports = regexp.MustCompile(`(?m)# !include:(.+.yaml)`)

// PreProcess all include directives
func PreProcess(data []byte) ([]byte, error) {
	// find all matches like !include:path\n
	matches := regexImports.FindAllSubmatch(data, -1)

	var replaceItems []string

	for _, match := range matches {
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
			// pad each line of file content with padBytes
			includeFileContent = bytes.ReplaceAll(includeFileContent, []byte("\n"), padBytes)

			replaceItems = append(replaceItems, matchString)
			replaceItems = append(replaceItems, string(includeFileContent))
		}
	}

	replacer := strings.NewReplacer(replaceItems...)

	return []byte(replacer.Replace(string(data))), nil
}
