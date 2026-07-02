package templates

import "github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"

type templateStatEntry struct {
	name        string
	description string
}

var templateStatEntries = []templateStatEntry{
	{
		name:        TemplateSyntaxWarningStats,
		description: "Found %d templates with syntax warning (use -validate flag for further examination)",
	},
	{
		name:        TemplateSyntaxErrorStats,
		description: "Found %d templates with syntax error (use -validate flag for further examination)",
	},
	{
		name:        TemplateRuntimeWarningStats,
		description: "Found %d templates with runtime error (use -validate flag for further examination)",
	},
	{
		name:        SkippedUnverifiedCodeTemplateStats,
		description: "Found %d unsigned or tampered code template (carefully examine before using it & use -sign flag to sign them)",
	},
	{
		name:        SkippedUnverifiedJavascriptTemplateStats,
		description: "Found %d unsigned or tampered javascript template (carefully examine before using it & use -sign flag to sign them)",
	},
	{
		name:        ExcludedHeadlessTemplateStats,
		description: "Excluded %d headless template[s] (disabled as default), use -headless option to run headless templates.",
	},
	{
		name:        ExcludedCodeTemplateStats,
		description: "Excluded %d code template[s] (disabled as default), use -code option to run code templates.",
	},
	{
		name:        ExcludedSelfContainedTemplateStats,
		description: "Excluded %d self-contained template[s] (disabled as default), use -esc option to run self-contained templates.",
	},
	{
		name:        ExcludedGlobalMatchersTemplateStats,
		description: "Excluded %d global matcher template[s] (disabled as default), use -enable-global-matchers option to run global matcher templates.",
	},
	{
		name:        ExcludedFileTemplateStats,
		description: "Excluded %d file template[s] (disabled as default), use -file option to run file templates.",
	},
	{
		name:        ExcludedWeakMatcherTemplateStats,
		description: "Excluded %d template[s] with known weak matchers / tags excluded from default run using .nuclei-ignore",
	},
	{
		name:        ExcludedDASTTemplateStats,
		description: "Excluded %d dast template[s] (disabled as default), use -dast option to run dast templates.",
	},
	{
		name:        SkippedUnverifiedTemplateStats,
		description: "Skipping %d unsigned template[s]",
	},
	{
		name:        SkippedRequestSignatureTemplateStats,
		description: "Skipping %d templates, HTTP Request signatures can only be used in Signed & Verified templates.",
	},
}

func init() {
	for _, entry := range templateStatEntries {
		stats.NewEntry(entry.name, entry.description)
	}
}
