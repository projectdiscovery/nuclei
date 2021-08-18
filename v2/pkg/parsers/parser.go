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

// LoadTemplate loads a template by parsing metadata and running all tag
// and path based filters on the template.
func LoadTemplate(templatePath string, tagFilter *filter.TagFilter) (bool, error) {
	return load(templatePath, false, nil, tagFilter)
}

// LoadTemplate loads a template by parsing metadata and running all tag
// based filters on the template.
//
// isWorkflow when false, means that the template itself is not a workflow
// however options tags may have been passed in workflowTags slice.
func LoadWorkflow(templatePath string, isWorkflow bool, tagFilter *filter.TagFilter, workflowTags []string) (bool, error) {
	return load(templatePath, isWorkflow, workflowTags, tagFilter)
}

func load(path string, isWorkflow bool, workflowTags []string, tagFilter *filter.TagFilter) (bool, error) {
	template, templateParseError := ParseTemplate(path)
	if templateParseError != nil {
		return false, templateParseError
	}
	// If this is called for a workflow and we don't have a workflow, return
	if isWorkflow && len(template.Workflows) == 0 {
		return false, nil
	}

	templateInfo := template.Info
	if validationError := validateMandatoryInfoFields(&templateInfo); validationError != nil {
		return false, validationError
	}

	// Validation of the metadata match happens in all scenarios.
	templateMatch, matchErr := isInfoMetadataMatch(tagFilter, &templateInfo, []string{})
	if matchErr != nil || !templateMatch {
		return false, matchErr
	}
	return true, nil
}

func isInfoMetadataMatch(tagFilter *filter.TagFilter, templateInfo *model.Info, workflowTags []string) (bool, error) {
	templateTags := templateInfo.Tags.ToSlice()
	templateAuthors := templateInfo.Authors.ToSlice()
	templateSeverity := templateInfo.SeverityHolder.Severity

	var match bool
	var err error
	if len(workflowTags) == 0 {
		match, err = tagFilter.Match(templateTags, templateAuthors, templateSeverity)
	} else {
		match, err = tagFilter.MatchWithWorkflowTags(templateTags, templateAuthors, templateSeverity, workflowTags)
	}
	if err == filter.ErrExcluded {
		return false, filter.ErrExcluded
	}

	return match, nil
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
