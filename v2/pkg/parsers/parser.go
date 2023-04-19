package parsers

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/cache"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
	"gopkg.in/yaml.v2"
)

const (
	errMandatoryFieldMissingFmt = "mandatory '%s' field is missing"
	errInvalidFieldFmt          = "invalid field format for '%s' (allowed format is %s)"
	warningFieldMissingFmt      = "field '%s' is missing"
)

// LoadTemplate returns true if the template is valid and matches the filtering criteria.
func LoadTemplate(templatePath string, tagFilter *filter.TagFilter, extraTags []string, catalog catalog.Catalog) (bool, error) {
	template, templateParseError := ParseTemplate(templatePath, catalog)
	if templateParseError != nil {
		return false, fmt.Errorf("Could not load template %s: %s\n", templatePath, templateParseError)
	}

	if len(template.Workflows) > 0 {
		return false, nil
	}

	validationError, validationWarning := validateTemplateFields(template)
	if validationError != nil {
		stats.Increment(SyntaxErrorStats)
		if validationWarning != nil {
			return false, fmt.Errorf("Could not load template %s: %s, with syntax warning: %s\n", templatePath, validationError, validationWarning)
		} else {
			return false, fmt.Errorf("Could not load template %s: %s\n", templatePath, validationError)
		}
	}
	// If we have warnings, we should still return true
	if validationWarning != nil {
		stats.Increment(SyntaxWarningStats)
		return true, fmt.Errorf("Loaded template %s: with syntax warning : %s\n", templatePath, validationWarning)
	}

	return isTemplateInfoMetadataMatch(tagFilter, template, extraTags)
}

// LoadWorkflow returns true if the workflow is valid and matches the filtering criteria.
func LoadWorkflow(templatePath string, catalog catalog.Catalog) (bool, error) {
	template, templateParseError := ParseTemplate(templatePath, catalog)
	if templateParseError != nil {
		return false, templateParseError
	}

	if len(template.Workflows) > 0 {
		if validationError, _ := validateTemplateFields(template); validationError != nil {
			stats.Increment(SyntaxErrorStats)
			return false, validationError
		}
		return true, nil
	}

	return false, nil
}

func isTemplateInfoMetadataMatch(tagFilter *filter.TagFilter, template *templates.Template, extraTags []string) (bool, error) {
	match, err := tagFilter.Match(template, extraTags)

	if err == filter.ErrExcluded {
		return false, filter.ErrExcluded
	}

	return match, err
}

func validateTemplateFields(template *templates.Template) (err error, warning error) {
	info := template.Info

	var errors []string
	var warnings []string

	if utils.IsBlank(info.Name) {
		errors = append(errors, fmt.Sprintf(errMandatoryFieldMissingFmt, "name"))
	}

	if info.Authors.IsEmpty() {
		errors = append(errors, fmt.Sprintf(errMandatoryFieldMissingFmt, "author"))
	}

	if template.ID == "" {
		errors = append(errors, fmt.Sprintf(errMandatoryFieldMissingFmt, "id"))
	} else if !templateIDRegexp.MatchString(template.ID) {
		errors = append(errors, fmt.Sprintf(errInvalidFieldFmt, "id", templateIDRegexp.String()))
	}

	if template.Type() != types.WorkflowProtocol && utils.IsBlank(info.SeverityHolder.Severity.String()) {
		warnings = append(warnings, fmt.Sprintf(warningFieldMissingFmt, "severity"))
	}

	if len(errors) > 0 {
		err = fmt.Errorf(strings.Join(errors, ", "))
	}
	if len(warnings) > 0 {
		warning = fmt.Errorf(strings.Join(warnings, ", "))
	}
	return
}

var (
	parsedTemplatesCache *cache.Templates
	ShouldValidate       bool
	NoStrictSyntax       bool
	templateIDRegexp     = regexp.MustCompile(`^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$`)
)

const (
	SyntaxWarningStats   = "syntax-warnings"
	SyntaxErrorStats     = "syntax-errors"
	RuntimeWarningsStats = "runtime-warnings"
)

func init() {
	parsedTemplatesCache = cache.New()

	stats.NewEntry(SyntaxWarningStats, "Found %d templates with syntax warning (use -validate flag for further examination)")
	stats.NewEntry(SyntaxErrorStats, "Found %d templates with syntax error (use -validate flag for further examination)")
	stats.NewEntry(RuntimeWarningsStats, "Found %d templates with runtime error (use -validate flag for further examination)")
}

// ParseTemplate parses a template and returns a *templates.Template structure
func ParseTemplate(templatePath string, catalog catalog.Catalog) (*templates.Template, error) {
	if value, err := parsedTemplatesCache.Has(templatePath); value != nil {
		return value.(*templates.Template), err
	}
	data, err := utils.ReadFromPathOrURL(templatePath, catalog)
	if err != nil {
		return nil, err
	}

	template := &templates.Template{}

	// check if the template is verified
	if signer.DefaultVerifier != nil {
		template.Verified, _ = signer.Verify(signer.DefaultVerifier, data)
	}

	switch config.GetTemplateFormatFromExt(templatePath) {
	case config.JSON:
		err = json.Unmarshal(data, template)
	case config.YAML:
		if NoStrictSyntax {
			err = yaml.Unmarshal(data, template)
		} else {
			err = yaml.UnmarshalStrict(data, template)
		}
	default:
		err = fmt.Errorf("failed to identify template format expected JSON or YAML but got %v", templatePath)
	}
	if err != nil {
		stats.Increment(SyntaxErrorStats)
		return nil, err
	}

	parsedTemplatesCache.Store(templatePath, template, nil)
	return template, nil
}
