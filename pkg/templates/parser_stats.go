package templates

const (
	TemplateRuntimeWarningStats = "template-runtime-warnings"
	TemplateSyntaxErrorStats    = "template-syntax-errors"
	TemplateSyntaxWarningStats  = "template-syntax-warnings"

	SkippedRequestSignatureTemplateStats     = "skipped-request-signature-templates"
	SkippedUnverifiedCodeTemplateStats       = "skipped-unverified-code-templates"
	SkippedUnverifiedJavascriptTemplateStats = "skipped-unverified-javascript-templates"
	SkippedUnverifiedTemplateStats           = "skipped-unverified-templates"

	ExcludedCodeTemplateStats           = "excluded-code-templates"
	ExcludedDASTTemplateStats           = "excluded-dast-templates"
	ExcludedFileTemplateStats           = "excluded-file-templates"
	ExcludedGlobalMatchersTemplateStats = "excluded-global-matcher-templates"
	ExcludedHeadlessTemplateStats       = "excluded-headless-templates"
	ExcludedSelfContainedTemplateStats  = "excluded-self-contained-templates"
	ExcludedWeakMatcherTemplateStats    = "excluded-weak-matcher-templates"
)

const (
	// Deprecated: Use TemplateSyntaxWarningStats instead.
	SyntaxWarningStats = TemplateSyntaxWarningStats
	// Deprecated: Use TemplateSyntaxErrorStats instead.
	SyntaxErrorStats = TemplateSyntaxErrorStats
	// Deprecated: Use TemplateRuntimeWarningStats instead.
	RuntimeWarningsStats = TemplateRuntimeWarningStats
	// Deprecated: Use SkippedUnverifiedCodeTemplateStats instead.
	SkippedCodeTmplTamperedStats = SkippedUnverifiedCodeTemplateStats
	// Deprecated: Use ExcludedHeadlessTemplateStats instead.
	ExcludedHeadlessTmplStats = ExcludedHeadlessTemplateStats
	// Deprecated: Use ExcludedWeakMatcherTemplateStats instead.
	TemplatesExcludedStats = ExcludedWeakMatcherTemplateStats
	// Deprecated: Use ExcludedCodeTemplateStats instead.
	ExcludedCodeTmplStats = ExcludedCodeTemplateStats
	// Deprecated: Use ExcludedDASTTemplateStats instead.
	ExcludedDastTmplStats = ExcludedDASTTemplateStats
	// Deprecated: Use SkippedUnverifiedTemplateStats instead.
	SkippedUnsignedStats = SkippedUnverifiedTemplateStats
	// Deprecated: Use ExcludedSelfContainedTemplateStats instead.
	ExcludedSelfContainedStats = ExcludedSelfContainedTemplateStats
	// Deprecated: Use ExcludedFileTemplateStats instead.
	ExcludedFileStats = ExcludedFileTemplateStats
	// Deprecated: Use SkippedRequestSignatureTemplateStats instead.
	SkippedRequestSignatureStats = SkippedRequestSignatureTemplateStats
)

// Deprecated: Use ExcludedDastTmplStats instead.
const ExludedDastTmplStats = ExcludedDastTmplStats
