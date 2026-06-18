package yaml

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	filepathutil "github.com/projectdiscovery/nuclei/v3/pkg/utils/filepath"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var reImportsPattern = regexp.MustCompile(`(?m)# !include:(.+.yaml)`)

// StrictSyntax determines if pre-processing directives should be observed
var StrictSyntax bool

// AllowLocalFileAccess mirrors the -allow-local-file-access (-lfa) option for
// the preprocessing stage. When false (the default), include directives are
// confined to the nuclei-templates directory and the including template's own
// directory.
var AllowLocalFileAccess bool

// PreProcess all include directives. templatePath is the path of the template
// currently being processed and is used to resolve relative include paths and
// to validate them.
func PreProcess(data []byte, templatePath string) ([]byte, error) {
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

		// resolve relative include paths against the including template's
		// directory rather than the process working directory.
		resolvedInclude := includeFileName
		if !filepath.IsAbs(resolvedInclude) && templatePath != "" {
			resolvedInclude = filepath.Join(filepath.Dir(templatePath), resolvedInclude)
		}

		// validate the include path unless local file access is enabled.
		if !AllowLocalFileAccess {
			if err := validateIncludePath(resolvedInclude, templatePath); err != nil {
				return nil, err
			}
		}

		// gets the number of tabs/spaces between the last \n and the beginning of the match
		matchIndex := bytes.Index(data, matchBytes)
		lastNewLineIndex := bytes.LastIndex(data[:matchIndex], []byte("\n"))
		padBytes := data[lastNewLineIndex:matchIndex]

		// check if the file exists
		if fileutil.FileExists(resolvedInclude) {
			// and in case replace the comment with it
			includeFileContent, err := os.ReadFile(resolvedInclude)
			if err != nil {
				return nil, err
			}
			// if it's yaml, tries to preprocess that too recursively
			if stringsutil.HasSuffixAny(resolvedInclude, extensions.YAML) {
				if subIncludedFileContent, err := PreProcess(includeFileContent, resolvedInclude); err == nil {
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

// validateIncludePath checks that an include path resolves within the
// nuclei-templates directory or the including template's directory, and is not
// a hard-linked regular file.
func validateIncludePath(includePath, templatePath string) error {
	allowedDirs := []string{config.DefaultConfig.GetTemplateDir()}
	if templatePath != "" {
		allowedDirs = append(allowedDirs, filepath.Dir(templatePath))
	}
	if !filepathutil.IsPathWithinAnyDirectory(includePath, allowedDirs...) {
		return errkit.Newf("include path %v is outside the templates directory and -lfa is not enabled", includePath)
	}
	if filepathutil.IsHardLinkedRegularFile(includePath) {
		return errkit.Newf("include path %v denied (hard link)", includePath)
	}
	return nil
}
