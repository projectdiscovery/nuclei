package utils

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

const (
	// TemplatesRepoURL is the URL for files in nuclei-templates repository
	TemplatesRepoURL = "https://templates.nuclei.sh/public/"
)

// TemplatePathURL returns the Path and URL for the provided template
func TemplatePathURL(fullPath, templateId string) (string, string) {
	if IsCustomTemplate(fullPath) {
		return "", ""
	}

	relativePath := strings.TrimPrefix(strings.TrimPrefix(fullPath, config.DefaultConfig.TemplatesDirectory), "/")
	templateURL := TemplatesRepoURL + templateId
	return relativePath, templateURL
}
