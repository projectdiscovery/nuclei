package templates

import "github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"

func init() {
	stats.NewEntry(SyntaxWarningStats, "Found %d templates with syntax warning (use -validate flag for further examination)")
	stats.NewEntry(SyntaxErrorStats, "Found %d templates with syntax error (use -validate flag for further examination)")
	stats.NewEntry(RuntimeWarningsStats, "Found %d templates with runtime error (use -validate flag for further examination)")
	stats.NewEntry(SkippedCodeTmplTamperedStats, "Found %d unsigned or tampered code template (carefully examine before using it & use -sign flag to sign them)")
	stats.NewEntry(ExcludedHeadlessTmplStats, "Excluded %d headless template[s] (disabled as default), use -headless option to run headless templates.")
	stats.NewEntry(ExcludedCodeTmplStats, "Excluded %d code template[s] (disabled as default), use -code option to run code templates.")
	stats.NewEntry(ExcludedSelfContainedStats, "Excluded %d self-contained template[s] (disabled as default), use -esc option to run self-contained templates.")
	stats.NewEntry(ExcludedFileStats, "Excluded %d file template[s] (disabled as default), use -file option to run file templates.")
	stats.NewEntry(TemplatesExcludedStats, "Excluded %d template[s] with known weak matchers / tags excluded from default run using .nuclei-ignore")
	stats.NewEntry(ExludedDastTmplStats, "Excluded %d dast template[s] (disabled as default), use -dast option to run dast templates.")
	stats.NewEntry(SkippedUnsignedStats, "Skipping %d unsigned template[s]")
	stats.NewEntry(SkippedRequestSignatureStats, "Skipping %d templates, HTTP Request signatures can only be used in Signed & Verified templates.")
}
