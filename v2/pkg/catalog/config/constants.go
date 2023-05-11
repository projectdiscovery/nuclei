package config

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

const (
	TemplateConfigFileName           = ".templates-config.json"
	NucleiTemplatesDirName           = "nuclei-templates"
	OfficialNucleiTeamplatesRepoName = "nuclei-templates"
	NucleiIgnoreFileName             = ".nuclei-ignore"
	NucleiTemplatesIndexFileName     = ".templates-index" // contains index of official nuclei templates
	NucleiTemplatesCheckSumFileName  = ".checksum"
	NewTemplateAdditionsFileName     = ".new-additions"
	CLIConifgFileName                = "config.yaml"
	ReportingConfigFilename          = "reporting-config.yaml"
	// Version is the current version of nuclei
	Version = `v2.9.4`

	// Directory Names of custom templates
	CustomS3TemplatesDirName     = "s3"
	CustomGithubTemplatesDirName = "github"
	CustomAzureTemplatesDirName  = "azure"
	CustomGitLabTemplatesDirName = "gitlab"
)

// IsOutdatedVersion compares two versions and returns true
// if current version is outdated
func IsOutdatedVersion(current, latest string) bool {
	if latest == "" {
		// if pdtm api call failed it's assumed that current version is outdated
		// and it will be confirmed while updating from github
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

func trimDevIfExists(version string) string {
	if strings.HasSuffix(version, "-dev") {
		return strings.TrimSuffix(version, "-dev")
	}
	return version
}
