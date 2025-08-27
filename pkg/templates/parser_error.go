package templates

import (
	"fmt"

	"github.com/projectdiscovery/utils/errkit"
)

// Helper functions for template errors with formatting
func ErrMandatoryFieldMissingFmt(field string) error {
	return errkit.New(fmt.Sprintf("mandatory '%s' field is missing", field)).Build()
}

func ErrInvalidField(field, format string) error {
	return errkit.New(fmt.Sprintf("invalid field format for '%s' (allowed format is %s)", field, format)).Build()
}

func ErrWarningFieldMissing(field string) error {
	return errkit.New(fmt.Sprintf("field '%s' is missing", field)).Build()
}

func ErrCouldNotLoadTemplate(path, reason string) error {
	return errkit.New(fmt.Sprintf("Could not load template %s: %s", path, reason)).Build()
}

func ErrLoadedWithWarnings(path, warning string) error {
	return errkit.New(fmt.Sprintf("Loaded template %s: with syntax warning : %s", path, warning)).Build()
}
