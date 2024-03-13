package templates

const (
	SyntaxWarningStats       = "syntax-warnings"
	SyntaxErrorStats         = "syntax-errors"
	RuntimeWarningsStats     = "runtime-warnings"
	UnsignedCodeWarning      = "unsigned-warnings"
	HeadlessFlagWarningStats = "headless-flag-missing-warnings"
	TemplatesExecutedStats   = "templates-executed"
	CodeFlagWarningStats     = "code-flag-missing-warnings"
	// Note: this is redefined in workflows.go to avoid circular dependency, so make sure to keep it in sync
	SkippedUnsignedStatsTODO = "skipped-unsigned-stats" // tracks loading of unsigned templates
)
