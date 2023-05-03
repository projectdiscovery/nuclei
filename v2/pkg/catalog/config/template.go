package config

import (
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates/extensions"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// TemplateFormat
type TemplateFormat uint8

const (
	YAML TemplateFormat = iota
	JSON
	Unknown
)

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

// GetSupportedTemplateFileExtensions returns all supported template file extensions
func GetSupportTemplateFileExtensions() []string {
	return []string{extensions.YAML, extensions.JSON}
}

// isTemplate is a callback function used by goflags to decide if given file should be read
// if it is not a nuclei-template file only then file is read
func IsTemplate(filename string) bool {
	return stringsutil.EqualFoldAny(filepath.Ext(filename), GetSupportTemplateFileExtensions()...)
}
