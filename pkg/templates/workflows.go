package templates

import (
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/keys"
	"github.com/projectdiscovery/nuclei/v3/pkg/model"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v3/pkg/workflows"
)

// compileWorkflow compiles the workflow for execution
func compileWorkflow(path string, preprocessor Preprocessor, options *protocols.ExecutorOptions, workflow *workflows.Workflow, loader model.WorkflowLoader) {
	for _, workflow := range workflow.Workflows {
		if err := parseWorkflow(preprocessor, workflow, options, loader); err != nil {
			gologger.Warning().Msgf("Could not parse workflow %s: %v\n", path, err)
			continue
		}
	}
}

// parseWorkflow parses and compiles all templates in a workflow recursively
func parseWorkflow(preprocessor Preprocessor, workflow *workflows.WorkflowTemplate, options *protocols.ExecutorOptions, loader model.WorkflowLoader) error {
	shouldNotValidate := false

	if workflow.Template == "" && workflow.Tags.IsEmpty() {
		return errors.New("invalid workflow with no templates or tags")
	}
	if len(workflow.Subtemplates) > 0 || len(workflow.Matchers) > 0 {
		shouldNotValidate = true
	}
	if err := parseWorkflowTemplate(workflow, preprocessor, options, loader, shouldNotValidate); err != nil {
		return err
	}
	for _, subtemplates := range workflow.Subtemplates {
		if err := parseWorkflow(preprocessor, subtemplates, options, loader); err != nil {
			gologger.Warning().Msgf("Could not parse workflow: %v\n", err)
			continue
		}
	}
	for _, matcher := range workflow.Matchers {
		if len(matcher.Name.ToSlice()) > 0 {
			if err := matcher.Compile(); err != nil {
				return errors.Wrap(err, "could not compile workflow matcher")
			}
		}
		for _, subtemplates := range matcher.Subtemplates {
			if err := parseWorkflow(preprocessor, subtemplates, options, loader); err != nil {
				gologger.Warning().Msgf("Could not parse workflow: %v\n", err)
				continue
			}
		}
	}
	return nil
}

// parseWorkflowTemplate parses a workflow template creating an executer
func parseWorkflowTemplate(workflow *workflows.WorkflowTemplate, preprocessor Preprocessor, options *protocols.ExecutorOptions, loader model.WorkflowLoader, noValidate bool) error {
	var paths []string

	subTemplateTags := workflow.Tags
	if !subTemplateTags.IsEmpty() {
		paths = loader.GetTemplatePathsByTags(subTemplateTags.ToSlice())
	} else {
		paths = loader.GetTemplatePaths([]string{workflow.Template}, noValidate)
	}
	if len(paths) == 0 {
		return nil
	}

	var workflowTemplates []*Template

	caps := CapabilitiesFromOptions(options.Options)
	for _, path := range paths {
		template, err := Parse(path, preprocessor, options.Copy())
		if err != nil {
			gologger.Warning().Msgf("Could not parse workflow template %s: %v\n", path, err)
			continue
		}

		if template == nil {
			continue
		}

		if template.Executer == nil {
			gologger.Warning().Msgf("Could not parse workflow template %s: no executer found\n", path)
			continue
		}

		if options.Options.DisableUnsignedTemplates && !template.Verified {
			// skip unverified templates when prompted to do so
			stats.Increment(SkippedUnverifiedTemplateStats)
			continue
		}

		if template.HasCodeRequest() && !template.Verified {
			// unverified code templates are not allowed in workflows
			stats.Increment(SkippedUnverifiedCodeTemplateStats)
			gologger.Warning().Msgf("Skipping unverified code template(s) from workflow: %v\n", path)
			continue
		}

		if template.IsUnsignedJavascriptTemplate() {
			// unverified javascript templates are not allowed in workflows
			stats.Increment(SkippedUnverifiedJavascriptTemplateStats)
			gologger.Warning().Msgf("Skipping unverified javascript template(s) from workflow: %v\n", path)
			continue
		}

		if missingCaps := template.MissingLoadCapabilities(caps); len(missingCaps) > 0 {
			for _, capability := range missingCaps {
				stats.Increment(capability.Stat())
				gologger.Warning().Msgf("Skipping workflow subtemplate: %s", capability.MissingFlagMessage(path))
			}
			continue
		}

		if template.UsesRequestSignature() && !template.Verified {
			stats.Increment(SkippedRequestSignatureTemplateStats)
			continue
		}

		// increment signed/unsigned counters
		if template.Verified {
			if template.TemplateVerifier == "" {
				SignatureStats[keys.PDVerifier].Add(1)
			} else {
				SignatureStats[template.TemplateVerifier].Add(1)
			}
		} else {
			SignatureStats[Unsigned].Add(1)
		}
		workflowTemplates = append(workflowTemplates, template)
	}

	finalTemplates, _, _ := ClusterTemplates(workflowTemplates, options.Copy())
	for _, template := range finalTemplates {
		workflow.Executers = append(workflow.Executers, &workflows.ProtocolExecuterPair{
			Executer:     template.Executer,
			Options:      options,
			TemplateType: template.Type(),
		})
	}

	return nil
}
