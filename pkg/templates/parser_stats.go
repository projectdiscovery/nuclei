package templates

const (
	SyntaxWarningStats           = "syntax-warnings"
	SyntaxErrorStats             = "syntax-errors"
	RuntimeWarningsStats         = "runtime-warnings"
	SkippedCodeTmplTamperedStats = "unsigned-warnings"
	ExcludedHeadlessTmplStats    = "headless-flag-missing-warnings"
	TemplatesExcludedStats       = "templates-executed"
	ExcludedCodeTmplStats        = "code-flag-missing-warnings"
	ExludedDastTmplStats         = "fuzz-flag-missing-warnings"
	SkippedUnsignedStats         = "skipped-unsigned-stats" // tracks loading of unsigned templates
	ExcludedSelfContainedStats   = "excluded-self-contained-stats"
	ExcludedFileStats            = "excluded-file-stats"
	SkippedRequestSignatureStats = "skipped-request-signature-stats"
)
