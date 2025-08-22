package config

import (
	"strings"

	"github.com/Masterminds/semver/v3"
)

type AppMode string

const (
	AppModeLibrary AppMode = "library"
	AppModeCLI     AppMode = "cli"
)

var (
	// Global Var to control behaviours specific to cli or library
	// maybe this should be moved to utils ??
	// this is overwritten in cmd/nuclei/main.go
	CurrentAppMode = AppModeLibrary
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
	Version = `v3.4.9`
	// Directory Names of custom templates
	CustomS3TemplatesDirName     = "s3"
	CustomGitHubTemplatesDirName = "github"
	CustomAzureTemplatesDirName  = "azure"
	CustomGitLabTemplatesDirName = "gitlab"
	BinaryName                   = "nuclei"
	FallbackConfigFolderName     = ".nuclei-config"
	NucleiConfigDirEnv           = "NUCLEI_CONFIG_DIR"
)

// IsOutdatedVersion compares two versions and returns true
// if the current version is outdated
func IsOutdatedVersion(current, latest string) bool {
	if latest == "" {
		// NOTE(dwisiswant0): if PDTM API call failed or returned empty, we
		// cannot determine if templates are outdated w/o additional checks
		// return false to avoid unnecessary updates.
		return false
	}

	current = trimDevIfExists(current)
	currentVer, _ := semver.NewVersion(current)
	newVer, _ := semver.NewVersion(latest)

	if currentVer == nil || newVer == nil {
		// fallback to naive comparison - return true only if they are different
		return current != latest
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

// similar to go pattern of enabling debug related features
// we add custom/extra switches for debugging purposes
const (
	// DebugArgHostErrorStats is used to print host error stats
	// when it is closed
	DebugArgHostErrorStats = "host-error-stats"
	// DebugExportReqURLPattern is used to export request URL pattern
	DebugExportURLPattern = "req-url-pattern"
)
