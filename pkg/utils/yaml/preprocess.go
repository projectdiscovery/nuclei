package yaml

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	filepathutil "github.com/projectdiscovery/nuclei/v3/pkg/utils/filepath"
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var reImportsPattern = regexp.MustCompile(`(?m)# !include:(.+.yaml)`)

const maxIncludeDepth = 32

// StrictSyntax determines if pre-processing directives should be observed
var StrictSyntax bool

// AllowLocalFileAccess mirrors the -allow-local-file-access (-lfa) option for
// the preprocessing stage. When false (the default), include directives are
// confined to the nuclei-templates directory and the including template's own
// directory.
var AllowLocalFileAccess bool

// TemplateBaseDirProvider, when set, returns an additional directory under which
// include directives are permitted (in addition to the including template's own
// directory). It is wired up by the catalog/config package to avoid an import
// cycle between this low-level utility package and catalog/config.
var TemplateBaseDirProvider func() string

// PreProcess all include directives. templatePath is the path of the template
// currently being processed and is used to resolve relative include paths and
// to validate them.
func PreProcess(data []byte, templatePath string) ([]byte, error) {
	return preProcess(data, templatePath, make(map[string]struct{}), 0)
}

func preProcess(data []byte, templatePath string, includeStack map[string]struct{}, depth int) ([]byte, error) {
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

		// check if the file exists; otherwise leave the directive untouched
		if !fileutil.FileExists(resolvedInclude) {
			continue
		}

		includeFileContent, err := readIncludedFile(resolvedInclude, includeStack, depth)
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
		includeFileContent, err = preProcess(includeFileContent, includeFileName, includeStack, depth+1)
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

// validateIncludePath checks that an include path resolves within the
// nuclei-templates directory or the including template's directory, and is not
// a hard-linked regular file.
func validateIncludePath(includePath, templatePath string) error {
	var allowedDirs []string
	if TemplateBaseDirProvider != nil {
		if baseDir := TemplateBaseDirProvider(); baseDir != "" {
			allowedDirs = append(allowedDirs, baseDir)
		}
	}
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
