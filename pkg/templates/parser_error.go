package templates

import (
	"github.com/projectdiscovery/utils/errkit"
)

var (
	ErrMandatoryFieldMissingFmt = errkit.New("mandatory field is missing")
	ErrInvalidField             = errkit.New("invalid field format")
	ErrWarningFieldMissing      = errkit.New("field is missing")
	ErrCouldNotLoadTemplate     = errkit.New("could not load template")
	ErrLoadedWithWarnings       = errkit.New("loaded template with syntax warning")
)
