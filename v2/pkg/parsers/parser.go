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

// Load loads a template by parsing metadata and running all tag and path based filters on the template.
func Load(templatePath string, isWorkflow bool, workflowTags []string, tagFilter *filter.TagFilter) (bool, error) {
	template, templateParseError := parseTemplate(templatePath)
	if templateParseError != nil {
		return false, templateParseError
	}

	templateInfo := template.Info
	if validationError := validateMandatoryInfoFields(&templateInfo); validationError != nil {
		return false, validationError
	}

	if len(template.Workflows) > 0 {
		if isWorkflow {
			return true, nil // if a workflow is declared and this template is a workflow, then load
		} else { //nolint:indent-error-flow,revive // preferred: readability and extensibility
			return false, nil // if a workflow is declared and this template is not a workflow then do not load
		}
	} else if isWorkflow {
		return false, nil // if no workflows are declared and this template is a workflow then do not load
	} else { // if workflows are not declared and the template is not a workflow then parse it
		return isInfoMetadataMatch(tagFilter, &templateInfo, workflowTags)
	}
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

func parseTemplate(templatePath string) (*templates.Template, error) {
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
			gologger.Warning().Msgf("Could not load template %s: %s", templatePath, err)
		}
		return nil, err
	}
	return template, nil
}
