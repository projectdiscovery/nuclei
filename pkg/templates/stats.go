package templates

import "github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"

func init() {
	stats.NewEntry(SyntaxWarningStats, "Found %d templates with syntax warning (use -validate flag for further examination)")
	stats.NewEntry(SyntaxErrorStats, "Found %d templates with syntax error (use -validate flag for further examination)")
	stats.NewEntry(RuntimeWarningsStats, "Found %d templates with runtime error (use -validate flag for further examination)")
	stats.NewEntry(UnsignedCodeWarning, "Found %d unsigned or tampered code template (carefully examine before using it & use -sign flag to sign them)")
	stats.NewEntry(HeadlessFlagWarningStats, "Excluded %d headless template[s] (disabled as default), use -headless option to run headless templates.")
	stats.NewEntry(CodeFlagWarningStats, "Excluded %d code template[s] (disabled as default), use -code option to run code templates.")
	stats.NewEntry(TemplatesExecutedStats, "Excluded %d template[s] with known weak matchers / tags excluded from default run using .nuclei-ignore")
	stats.NewEntry(FuzzFlagWarningStats, "Excluded %d fuzz template[s] (disabled as default), use -fuzz option to run fuzz templates.")
	stats.NewEntry(SkippedUnsignedStats, "Skipping %d unsigned template[s]")
}
