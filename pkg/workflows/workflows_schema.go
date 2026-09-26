package workflows

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var workflowMetadata = []schema.PropertyMetadata{
	{
		PropName: "workflows",
		Description: schema.MultiLine(
			"List of workflow templates / tags to execute",
			"Example:",
			"```yaml",
			"workflows:",
			"  - template: http/technologies/",
			"  - tags: xss",
			"    subtemplates:",
			"      - tags: xss",
			"```",
		),
	},
}

var workflowTemplateMetadata = []schema.PropertyMetadata{
	{
		PropName: "template",
		Description: schema.MultiLine(
			"Template file or directory to execute as part of the workflow",
		),
		Example: schema.PropertyExamples("http/cves/", "network/detection/"),
	},
	{
		PropName: "tags",
		RemoveRef: true,
		OneOf: []*schema.PropertyMetadata{
			{
				PropType:    "string",
				Description: schema.MultiLine("Comma-separated tags used to select templates"),
				Example:     schema.PropertyExample("cve,xss"),
			},
			{
				PropType:    "array",
				Description: schema.MultiLine("List of tags used to select templates"),
				Example:     schema.PropertyExample([]string{"cve", "xss"}),
			},
		},
	},
	{
		PropName: "matchers",
		Description: schema.MultiLine(
			"Name-based matchers that decide which subtemplates to run",
		),
	},
	{
		PropName: "subtemplates",
		Description: schema.MultiLine(
			"Nested workflow entries ran when the parent template/tag matches",
		),
	},
}

var workflowTemplateAnyOfRequired = []schema.RequiredCombos{
	schema.Require("template"),
	schema.Require("tags"),
}

// JSONSchemaExtend extends the Workflow JSON schema.
func (Workflow) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(workflowMetadata, base)
}

// JSONSchemaExtend extends the WorkflowTemplate JSON schema.
func (WorkflowTemplate) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(workflowTemplateMetadata, base)
	schema.ApplyAnyOfRequired(workflowTemplateAnyOfRequired, base)
}
