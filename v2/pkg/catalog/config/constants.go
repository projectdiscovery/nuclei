package config

import "github.com/Masterminds/semver/v3"

const (
	TemplateConfigFileName           = ".templates-config.json"
	NucleiTemplatesDirName           = "nuclei-templates"
	CustomS3TemplatesDirName         = "s3"
	CustomGithubTemplatesDirName     = "github"
	OfficialNucleiTeamplatesRepoName = "nuclei-templates"
	NucleiIgnoreFileName             = ".nuclei-ignore"
	NewTemplateAdditionsFileName     = ".new-additions"
	// Version is the current version of nuclei
	Version = `2.9.2-dev`
)

// IsOutdatedVersion compares two versions and returns true
// if current version is outdated
func IsOutdatedVersion(current, latest string) bool {
	if latest == "" {
		return false
	}
	currentVer, _ := semver.NewVersion(current)
	newVer, _ := semver.NewVersion(latest)
	if currentVer == nil || newVer == nil {
		// fallback to naive comparison
		return current == latest
	}
	return newVer.GreaterThan(currentVer)
}
