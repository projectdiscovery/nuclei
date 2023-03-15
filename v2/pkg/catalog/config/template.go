package config

import "strings"

// TemplateFormat
type TemplateFormat uint8

const (
	YAML TemplateFormat = iota
	JSON
	Unknown
)

// GetTemplateFormatFromExt returns template format
func GetTemplateFormatFromExt(filePath string) TemplateFormat {
	if strings.HasSuffix(filePath, ".json") {
		return JSON
	}
	if strings.HasSuffix(filePath, ".yaml") {
		return YAML
	}
	return Unknown
}

// GetSupportedTemplateFileExtensions returns all supported template file extensions
func GetSupportTemplateFileExtensions() []string {
	return []string{".yaml", ".json"}
}
