package config

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	TemplateConfigFileName          = ".templates-config.json"
	NucleiTemplatesDirName          = "nuclei-templates"
	OfficialNucleiTemplatesRepoName = "nuclei-templates"
	NucleiIgnoreFileName            = ".nuclei-ignore"
	NucleiTemplatesIndexFileName    = ".templates-index" // contains index of official nuclei templates
	NucleiTemplatesCheckSumFileName = ".checksum"
	NewTemplateAdditionsFileName    = ".new-additions"
	CLIConfigFileName               = "config.yaml"
	ReportingConfigFilename         = "reporting-config.yaml"
	// Version is the current version of nuclei
	Version = `v2.9.15`
	// Directory Names of custom templates
	CustomS3TemplatesDirName     = "s3"
	CustomGitHubTemplatesDirName = "github"
	CustomAzureTemplatesDirName  = "azure"
	CustomGitLabTemplatesDirName = "gitlab"
)

// IsOutdatedVersion compares two versions and returns true
// if the current version is outdated
func IsOutdatedVersion(current, latest string) bool {
	if latest == "" {
		// if pdtm api call failed it's assumed that the current version is outdated
		// and it will be confirmed while updating from GitHub
		// this fixes `version string empty` errors
		return true
	}
	current = trimDevIfExists(current)
	currentVer, _ := semver.NewVersion(current)
	newVer, _ := semver.NewVersion(latest)
	if currentVer == nil || newVer == nil {
		// fallback to naive comparison
		return current == latest
	}
	return newVer.GreaterThan(currentVer)
}

// trimDevIfExists trims `-dev` suffix from version string if it exists
func trimDevIfExists(version string) string {
	if strings.HasSuffix(version, "-dev") {
		return strings.TrimSuffix(version, "-dev")
	}
	return version
}
