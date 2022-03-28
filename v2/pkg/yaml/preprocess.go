package yaml

import (
	"bufio"
	"bytes"
	"log"
	"os"
	"regexp"
	"strings"
	"text/template"

	"github.com/projectdiscovery/fileutil"
	"github.com/projectdiscovery/stringsutil"
	"github.com/rs/xid"
	"gopkg.in/yaml.v3"
)

var (
	regexImports = regexp.MustCompile(`(?m)# !include:(.+[].yaml|+.yamlc])$`)
)

// PreProcess all include directives
func PreProcess(data []byte) ([]byte, error) {
	// find all matches like !include:path\n
	importMatches := regexImports.FindAllSubmatch(data, -1)

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
			switch {
			// if it's yaml, tries to preprocess that too recursively
			case stringsutil.HasSuffixAny(includeFileName, ".yaml"):
				if subIncludedFileContent, err := PreProcess(includeFileContent); err == nil {
					includeFileContent = subIncludedFileContent
				} else {
					log.Println(err)
				}
			// if it's yamlc, it needs to be compiled
			case stringsutil.HasSuffixAny(includeFileName, ".yamlc"):
				if subIncludedFileContent, err := preRender(includeFileContent); err == nil {
					includeFileContent = subIncludedFileContent
				} else {
					log.Println(err)
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

func preRender(compileData []byte) ([]byte, error) {
	// Line comments are yaml code (for now we support only inline lists)
	// the rest is templating
	var yamlCode, tplCode bytes.Buffer
	scanner := bufio.NewScanner(bytes.NewReader(compileData))
	for scanner.Scan() {
		codeLine := scanner.Text()
		switch {
		case stringsutil.HasPrefixAny(codeLine, "# "):
			yamlCode.WriteString(strings.TrimPrefix(codeLine, "# ") + "\n")
		default:
			tplCode.WriteString(codeLine + "\n")
		}
	}

	// unmarshal yaml
	yamlMap := make(map[string]interface{})
	if err := yaml.Unmarshal(yamlCode.Bytes(), &yamlMap); err != nil {
		return compileData, err
	}

	// randomName
	id := xid.New()
	// render template with yaml map
	tp, err := template.New(id.String()).Parse(tplCode.String())
	if err != nil {
		return compileData, err
	}

	var tplRendered bytes.Buffer
	err = tp.Execute(&tplRendered, yamlMap)
	if err != nil {
		return compileData, err
	}

	return tplRendered.Bytes(), nil
}
