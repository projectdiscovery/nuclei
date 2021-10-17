package utils

import (
	"strings"
)

const (
	NUCLEI_TEMPLATES_REPO_URL = "https://github.com/projectdiscovery/nuclei-templates/blob/master"
)

func IsBlank(value string) bool {
	return strings.TrimSpace(value) == ""
}

func IsNotBlank(value string) bool {
	return !IsBlank(value)
}

func TemplatePath(fullPath string) (string, string) {
	parts := strings.Split(fullPath, "/nuclei-templates/")
	templateFile := parts[1]
	templateFileURL := NUCLEI_TEMPLATES_REPO_URL + templateFile
	return templateFile, templateFileURL
}
