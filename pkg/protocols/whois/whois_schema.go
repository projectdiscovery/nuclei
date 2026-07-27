package whois

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var whoisRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine("Optional ID of this WHOIS request block"),
		Example:     schema.PropertyExample("whois-lookup"),
	},
	{
		PropName: "query",
		Description: schema.MultiLine(
			"Query for the WHOIS request",
			"Example:",
			"```yaml",
			"query: \"{{FQDN}}\"",
			"```",
		),
		Example: schema.PropertyExamples("{{FQDN}}", "example.com"),
	},
	{
		PropName: "server",
		Description: schema.MultiLine(
			"Optional WHOIS server URL to execute the request on",
			"Example:",
			"```yaml",
			"server: \"whois.verisign-grs.com:43\"",
			"```",
		),
		Example: schema.PropertyExample("whois.verisign-grs.com:43"),
	},
}

var whoisRequestAnyOfRequired = []schema.RequiredCombos{
	schema.Require("query"),
}

// JSONSchemaExtend extends the WHOIS request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(whoisRequestMetadata, base)
	schema.ApplyAnyOfRequired(whoisRequestAnyOfRequired, base)
}
