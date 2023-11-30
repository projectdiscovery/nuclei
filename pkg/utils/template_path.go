package utils

import (
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
)

const (
	// TemplatesRepoURL is the URL for files in nuclei-templates repository
	TemplatesRepoURL = "https://cloud.projectdiscovery.io/public/"
)

// TemplatePathURL returns the Path and URL for the provided template
func TemplatePathURL(fullPath, templateId string) (string, string) {
	var templateDirectory string
	configData := config.DefaultConfig
	if configData.TemplatesDirectory != "" && strings.HasPrefix(fullPath, configData.TemplatesDirectory) {
		templateDirectory = configData.TemplatesDirectory
	} else {
		return "", ""
	}

	finalPath := strings.TrimPrefix(strings.TrimPrefix(fullPath, templateDirectory), "/")
	templateURL := TemplatesRepoURL + templateId
	return finalPath, templateURL
}
