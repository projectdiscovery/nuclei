package workflows

import (
	"errors"
	"strings"

	"github.com/segmentio/ksuid"
)

// generateLogicFromWorkflows generates a workflow logic using the
// yaml based workflow declaration.
//
// The implementation is very basic and contains a simple yaml->tengo
// convertor that implements basic required features.
func (w *Workflow) generateLogicFromWorkflows() error {
	w.Variables = make(map[string]string)

	workflowBuilder := &strings.Builder{}
	for _, template := range w.Workflows {
		if err := w.generateTemplateFunc(template, workflowBuilder); err != nil {
			return err
		}
	}
	w.Logic = workflowBuilder.String()
	return nil
}

func (w *Workflow) generateTemplateFunc(template *WorkflowTemplate, workflowBuilder *strings.Builder) error {
	builder := &strings.Builder{}
	builder.WriteString("var_")
	builder.WriteString(ksuid.New().String())
	ID := builder.String()
	w.Variables[ID] = template.Template

	if len(template.Subtemplates) > 0 && len(template.Matchers) > 0 {
		return errors.New("subtemplates and matchers cannot be present together")
	}
	workflowBuilder.WriteRune('\n')
	if len(template.Matchers) > 0 {
		workflowBuilder.WriteString(ID)
		workflowBuilder.WriteString("()\n")

		for _, matcher := range template.Matchers {
			if len(matcher.Subtemplates) == 0 {
				return errors.New("no subtemplates present for matcher")
			}
			workflowBuilder.WriteString("\nif ")
			workflowBuilder.WriteString(ID)
			workflowBuilder.WriteString("[\"")
			workflowBuilder.WriteString(matcher.Name)
			workflowBuilder.WriteString("\"] {")

			for _, subtemplate := range matcher.Subtemplates {
				if err := w.generateTemplateFunc(subtemplate, workflowBuilder); err != nil {
					return err
				}
			}
			workflowBuilder.WriteString("\n}")
		}
	}
	if len(template.Subtemplates) > 0 {
		workflowBuilder.WriteString("if ")
		workflowBuilder.WriteString(ID)
		workflowBuilder.WriteString("() {")

		for _, subtemplate := range template.Subtemplates {
			if err := w.generateTemplateFunc(subtemplate, workflowBuilder); err != nil {
				return err
			}
		}
		workflowBuilder.WriteString("\n}")
	}
	if len(template.Matchers) == 0 && len(template.Subtemplates) == 0 {
		workflowBuilder.WriteString(ID)
		workflowBuilder.WriteString("();")
	}
	return nil
}
