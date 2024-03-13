package templates

import (
	errorutil "github.com/projectdiscovery/utils/errors"
)

var (
	ErrMandatoryFieldMissingFmt = errorutil.NewWithFmt("mandatory '%s' field is missing")
	ErrInvalidField             = errorutil.NewWithFmt("invalid field format for '%s' (allowed format is %s)")
	ErrWarningFieldMissing      = errorutil.NewWithFmt("field '%s' is missing")
	ErrCouldNotLoadTemplate     = errorutil.NewWithFmt("Could not load template %s: %s")
	ErrLoadedWithWarnings       = errorutil.NewWithFmt("Loaded template %s: with syntax warning : %s")
)
