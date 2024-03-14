package templates

const (
	SyntaxWarningStats       = "syntax-warnings"
	SyntaxErrorStats         = "syntax-errors"
	RuntimeWarningsStats     = "runtime-warnings"
	UnsignedCodeWarning      = "unsigned-warnings"
	HeadlessFlagWarningStats = "headless-flag-missing-warnings"
	TemplatesExecutedStats   = "templates-executed"
	CodeFlagWarningStats     = "code-flag-missing-warnings"
	FuzzFlagWarningStats     = "fuzz-flag-missing-warnings"
	SkippedUnsignedStats     = "skipped-unsigned-stats" // tracks loading of unsigned templates
)
