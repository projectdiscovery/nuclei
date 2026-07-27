package file

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var fileRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine("Optional ID of this file request block"),
		Example:     schema.PropertyExample("file-secret"),
	},
	{
		PropName: "extensions",
		Description: schema.MultiLine(
			"List of extensions to perform matching on",
			"Use `all` to match every file",
			"Example:",
			"```yaml",
			"extensions:",
			"  - .txt",
			"  - .conf",
			"```",
		),
		Example: schema.PropertyExamples([]string{".txt", ".conf"}, []string{"all"}),
	},
	{
		PropName: "denylist",
		Description: schema.MultiLine(
			"Files, directories, and extensions to deny during matching",
		),
		Example: schema.PropertyExample([]string{".git", "node_modules"}),
	},
	{
		PropName: "max-size",
		Description: schema.MultiLine("Maximum size of the file to run the request on"),
		Example:     schema.PropertyExamples("5Mb", "1Kb"),
	},
	{
		PropName: "archive",
		Description: schema.MultiLine("Process compressed archives without unpacking"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "mime-type",
		Description: schema.MultiLine("Filter files by mime-type"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "no-recursive",
		Description: schema.MultiLine("Do not recurse into folders when directories are provided"),
		Example:     schema.PropertyExample(true),
	},
}

// JSONSchemaExtend extends the file request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(fileRequestMetadata, base)
}
