package code

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var codeRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine("Optional ID of this code request block"),
		Example:     schema.PropertyExample("code-py"),
	},
	{
		PropName: "engine",
		Description: schema.MultiLine(
			"Runtime engine(s) used to execute the source",
			"Example:",
			"```yaml",
			"engine:",
			"  - py",
			"  - python3",
			"```",
		),
		Example: schema.PropertyExamples([]string{"py", "python3"}, []string{"sh"}, []string{"powershell"}),
	},
	{
		PropName: "source",
		Description: schema.MultiLine(
			"Inline source snippet or file path to execute",
			"Example:",
			"```yaml",
			"source: |",
			"  print(\"hello\")",
			"```",
		),
	},
	{
		PropName: "args",
		Description: schema.MultiLine("Arguments passed to the code engine"),
		Example:     schema.PropertyExample([]string{"-c"}),
	},
	{
		PropName: "pattern",
		Description: schema.MultiLine("Optional pattern used by some engines for file selection"),
	},
	{
		PropName: "pre-condition",
		Description: schema.MultiLine(
			"JavaScript condition evaluated before executing the code request",
		),
		Example: schema.PropertyExample("len(Host) > 0"),
	},
	{
		PropName: "sandbox",
		Description: schema.MultiLine(
			"Optional sandbox configuration (working directory / image) for isolated execution",
		),
	},
}

var codeRequestAnyOfRequired = []schema.RequiredCombos{
	schema.Require("engine", "source"),
}

// JSONSchemaExtend extends the code request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(codeRequestMetadata, base)
	schema.ApplyAnyOfRequired(codeRequestAnyOfRequired, base)
}
