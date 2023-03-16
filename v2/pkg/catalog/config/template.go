package config

import (
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/templates/extensions"
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
