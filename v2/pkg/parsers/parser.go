package parsers

import (
	"fmt"
	"io/ioutil"
	"os"
	"regexp"

	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader/filter"
	"github.com/projectdiscovery/nuclei/v2/pkg/model"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
)

const mandatoryFieldMissingTemplate = "mandatory '%s' field is missing"

// LoadTemplate returns true if the template is valid and matches the filtering criteria.
func LoadTemplate(templatePath string, tagFilter *filter.TagFilter, extraTags []string) (bool, error) {
	template, templateParseError := ParseTemplate(templatePath)
	if templateParseError != nil {
		return false, templateParseError
	}

	if len(template.Workflows) > 0 {
		return false, nil
	}

	templateInfo := template.Info
	if validationError := validateMandatoryInfoFields(&templateInfo); validationError != nil {
		return false, validationError
	}

	return isTemplateInfoMetadataMatch(tagFilter, &templateInfo, extraTags)
}

// LoadWorkflow returns true if the workflow is valid and matches the filtering criteria.
func LoadWorkflow(templatePath string, tagFilter *filter.TagFilter) (bool, error) {
	template, templateParseError := ParseTemplate(templatePath)
	if templateParseError != nil {
		return false, templateParseError
	}

	templateInfo := template.Info

	if len(template.Workflows) > 0 {
		if validationError := validateMandatoryInfoFields(&templateInfo); validationError != nil {
			return false, validationError
		}

		return isTemplateInfoMetadataMatch(tagFilter, &templateInfo, nil) // we don't want workflows to be loaded by tags
	}

	return false, nil
}

func isTemplateInfoMetadataMatch(tagFilter *filter.TagFilter, templateInfo *model.Info, extraTags []string) (bool, error) {
	templateTags := templateInfo.Tags.ToSlice()
	templateAuthors := templateInfo.Authors.ToSlice()
	templateSeverity := templateInfo.SeverityHolder.Severity

	match, err := tagFilter.Match(templateTags, templateAuthors, templateSeverity, extraTags)

	if err == filter.ErrExcluded {
		return false, filter.ErrExcluded
	}

	return match, err
}

func validateMandatoryInfoFields(info *model.Info) error {
	if info == nil {
		return fmt.Errorf(mandatoryFieldMissingTemplate, "info")
	}

	if utils.IsBlank(info.Name) {
		return fmt.Errorf(mandatoryFieldMissingTemplate, "name")
	}

	if info.Authors.IsEmpty() {
		return fmt.Errorf(mandatoryFieldMissingTemplate, "author")
	}
	return nil
}

var fieldErrorRegexp = regexp.MustCompile(`not found in`)

// ParseTemplate parses a template and returns a *templates.Template structure
func ParseTemplate(templatePath string) (*templates.Template, error) {
	f, err := os.Open(templatePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}

	template := &templates.Template{}
	err = yaml.UnmarshalStrict(data, template)
	if err != nil {
		if fieldErrorRegexp.MatchString(err.Error()) {
			gologger.Warning().Msgf("Unrecognized fields in template %s: %s", templatePath, err)
			return template, nil
		}
		return nil, err
	}
	return template, nil
}
