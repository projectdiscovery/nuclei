package config

import (
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates/extensions"
	fileutil "github.com/projectdiscovery/utils/file"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	knownConfigFiles     = []string{"cves.json", "contributors.json", "TEMPLATES-STATS.json"}
	knownMiscDirectories = []string{".git", ".github", "helpers"}
)

// TemplateFormat
type TemplateFormat uint8

const (
	YAML TemplateFormat = iota
	JSON
	Unknown
)

// GetKnownConfigFiles returns known config files.
func GetKnownConfigFiles() []string {
	return knownConfigFiles
}

// GetKnownMiscDirectories returns known misc directories with trailing slashes.
//
// The trailing slash ensures that directory matching is explicit and avoids
// falsely match files with similar names (e.g. "helpers" matching
// "some-helpers.yaml"), since [IsTemplate] checks against normalized full paths.
func GetKnownMiscDirectories() []string {
	trailedSlashDirs := make([]string, 0, len(knownMiscDirectories))
	for _, dir := range knownMiscDirectories {
		trailedSlashDirs = append(trailedSlashDirs, dir+string(os.PathSeparator))
	}

	return trailedSlashDirs
}

// GetTemplateFormatFromExt returns template format
func GetTemplateFormatFromExt(filePath string) TemplateFormat {
	fileExt := strings.ToLower(filepath.Ext(filePath))
	switch fileExt {
	case extensions.JSON:
		return JSON
	case extensions.YAML:
		return YAML
	default:
		return Unknown
	}
}

// GetSupportTemplateFileExtensions returns all supported template file extensions
func GetSupportTemplateFileExtensions() []string {
	return []string{extensions.YAML, extensions.JSON}
}

// IsTemplate returns true if the file is a template based on its path.
// It used by goflags and other places to filter out non-template files.
func IsTemplate(fpath string) bool {
	return IsTemplateWithRoot(fpath, "")
}

// IsTemplateWithRoot returns true if the file is a template based on its path
// and root directory. If rootDir is provided, it checks for excluded
// directories relative to the root.
func IsTemplateWithRoot(fpath, rootDir string) bool {
	fpath = filepath.FromSlash(fpath)
	fname := filepath.Base(fpath)
	fext := strings.ToLower(filepath.Ext(fpath))

	if stringsutil.ContainsAny(fname, GetKnownConfigFiles()...) {
		return false
	}

	var pathToCheck string
	if rootDir != "" {
		if filepath.IsAbs(fpath) {
			rel, err := filepath.Rel(rootDir, fpath)
			if err == nil && !strings.HasPrefix(rel, "..") {
				pathToCheck = rel
			} else {
				pathToCheck = fpath
			}
		} else {
			pathToCheck = fpath
		}
	} else {
		pathToCheck = fpath
	}

	// Only check components if pathToCheck is NOT absolute
	// This avoids false positives on parent directories for absolute paths
	if !filepath.IsAbs(pathToCheck) {
		parts := strings.Split(pathToCheck, string(os.PathSeparator))
		for _, p := range parts {
			for _, excluded := range knownMiscDirectories {
				if strings.EqualFold(p, excluded) {
					return false
				}
			}
		}
	}

	return stringsutil.EqualFoldAny(fext, GetSupportTemplateFileExtensions()...)
}

type template struct {
	ID string `json:"id" yaml:"id"`
}

// GetTemplateIDFromReader returns template id from reader
func GetTemplateIDFromReader(data io.Reader, filename string) (string, error) {
	var t template
	var err error
	switch GetTemplateFormatFromExt(filename) {
	case YAML:
		err = fileutil.UnmarshalFromReader(fileutil.YAML, data, &t)
	case JSON:
		err = fileutil.UnmarshalFromReader(fileutil.JSON, data, &t)
	}
	return t.ID, err
}

func getTemplateID(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}

	defer func() {
		_ = file.Close()
	}()
	return GetTemplateIDFromReader(file, filePath)
}

// GetTemplatesIndexFile returns map[template-id]: template-file-path
func GetNucleiTemplatesIndex() (map[string]string, error) {
	indexFile := DefaultConfig.GetTemplateIndexFilePath()
	index := map[string]string{}
	if fileutil.FileExists(indexFile) {
		f, err := os.Open(indexFile)
		if err == nil {
			csvReader := csv.NewReader(f)
			records, err := csvReader.ReadAll()
			if err == nil {
				for _, v := range records {
					if len(v) >= 2 {
						index[v[0]] = v[1]
					}
				}
				return index, nil
			}
		}
		DefaultConfig.Logger.Error().Msgf("failed to read index file creating new one: %v", err)
	}

	ignoreDirs := DefaultConfig.GetAllCustomTemplateDirs()

	// empty index if templates are not installed
	if !fileutil.FolderExists(DefaultConfig.TemplatesDirectory) {
		return index, nil
	}
	err := filepath.WalkDir(DefaultConfig.TemplatesDirectory, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			DefaultConfig.Logger.Verbose().Msgf("failed to walk path=%v err=%v", path, err)
			return nil
		}
		if d.IsDir() || !IsTemplateWithRoot(path, DefaultConfig.TemplatesDirectory) || stringsutil.ContainsAny(path, ignoreDirs...) {
			return nil
		}
		// get template id from file
		id, err := getTemplateID(path)
		if err != nil || id == "" {
			DefaultConfig.Logger.Verbose().Msgf("failed to get template id from file=%v got id=%v err=%v", path, id, err)
			return nil
		}
		index[id] = path
		return nil
	})
	return index, err
}
