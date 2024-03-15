package templates

import (
	"errors"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
)

// validateTemplateMandatoryFields validates the mandatory fields of a template
// return error from this function will cause hard fail and not proceed further
func validateTemplateMandatoryFields(template *Template) error {
	info := template.Info

	var validateErrors []error

	if utils.IsBlank(info.Name) {
		validateErrors = append(validateErrors, ErrMandatoryFieldMissingFmt.Msgf("name"))
	}

	if info.Authors.IsEmpty() {
		validateErrors = append(validateErrors, ErrMandatoryFieldMissingFmt.Msgf("author"))
	}

	if template.ID == "" {
		validateErrors = append(validateErrors, ErrMandatoryFieldMissingFmt.Msgf("id"))
	} else if !ReTemplateID.MatchString(template.ID) {
		validateErrors = append(validateErrors, ErrInvalidField.Msgf("id", ReTemplateID.String()))
	}

	if len(validateErrors) > 0 {
		return errors.Join(validateErrors...)
	}

	return nil
}

func isTemplateInfoMetadataMatch(tagFilter *TagFilter, template *Template, extraTags []string) (bool, error) {
	match, err := tagFilter.Match(template, extraTags)

	if err == ErrExcluded {
		return false, ErrExcluded
	}

	return match, err
}

// validateTemplateOptionalFields validates the optional fields of a template
// return error from this function will throw a warning and proceed further
func validateTemplateOptionalFields(template *Template) error {
	info := template.Info

	var warnings []error

	if template.Type() != types.WorkflowProtocol && utils.IsBlank(info.SeverityHolder.Severity.String()) {
		warnings = append(warnings, ErrWarningFieldMissing.Msgf("severity"))
	}

	if len(warnings) > 0 {
		return errors.Join(warnings...)
	}

	return nil
}
