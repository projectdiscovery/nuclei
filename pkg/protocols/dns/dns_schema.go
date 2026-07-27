package dns

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var dnsRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine(
			"Optional ID of this DNS request block",
			"Useful when calling / executing this request block from flow",
		),
		Example: schema.PropertyExample("dns-a-lookup"),
	},
	{
		PropName: "name",
		Description: schema.MultiLine(
			"Hostname to make the DNS request for",
			"Example:",
			"```yaml",
			"- name: \"{{FQDN}}\"",
			"```",
		),
		Example: schema.PropertyExamples("{{FQDN}}", "{{Hostname}}"),
	},
	{
		PropName: "type",
		Description: schema.MultiLine(
			"DNS request type",
			"Supported values: A, NS, DS, CNAME, SOA, PTR, MX, TXT, AAAA, CAA, TLSA, ANY, SRV",
		),
		Example: schema.PropertyExamples("A", "AAAA", "CNAME", "MX", "TXT"),
	},
	{
		PropName: "class",
		Description: schema.MultiLine(
			"DNS request class",
			"Supported values: inet, csnet, chaos, hesiod, none, any",
		),
		Example: schema.PropertyExample("inet"),
		Default: "inet",
	},
	{
		PropName: "retries",
		Description: schema.MultiLine("Number of retries for the DNS request"),
		Example:     schema.PropertyExample(3),
	},
	{
		PropName: "resolvers",
		Description: schema.MultiLine(
			"Custom resolvers to use for this request",
			"Example:",
			"```yaml",
			"resolvers:",
			"  - 1.1.1.1",
			"  - 8.8.8.8",
			"```",
		),
		Example: schema.PropertyExample([]string{"1.1.1.1", "8.8.8.8"}),
	},
	{
		PropName: "recursion",
		Description: schema.MultiLine("Whether the resolver should recurse records"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "trace",
		Description: schema.MultiLine("Perform a DNS trace operation for the target"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "payloads",
		Description: schema.MultiLine(
			"Payloads for the DNS request",
			"Referenced payload keys are iterated and replaced in the request",
		),
	},
	{
		PropName: "attack",
		Description: schema.MultiLine(
			"Payload combination strategy when payloads are defined",
			"Supported values: batteringram, pitchfork, clusterbomb",
		),
		Example: schema.PropertyExamples("batteringram", "pitchfork", "clusterbomb"),
	},
}

var dnsRequestAnyOfRequired = []schema.RequiredCombos{
	schema.Require("name"),
}

// JSONSchemaExtend extends the DNS request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(dnsRequestMetadata, base)
	schema.ApplyAnyOfRequired(dnsRequestAnyOfRequired, base)
}
