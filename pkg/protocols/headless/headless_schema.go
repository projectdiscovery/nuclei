package headless

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var headlessRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine("Optional ID of this headless request block"),
		Example:     schema.PropertyExample("headless-login"),
	},
	{
		PropName: "steps",
		Description: schema.MultiLine(
			"List of browser actions to run for the headless request",
			"Example:",
			"```yaml",
			"steps:",
			"  - action: navigate",
			"    args:",
			"      url: \"{{BaseURL}}\"",
			"  - action: waitload",
			"```",
		),
	},
	{
		PropName: "user_agent",
		Description: schema.MultiLine(
			"Built-in user agent selection for the headless request",
			"Supported values depend on UserAgentHolder enums",
		),
	},
	{
		PropName: "custom_user_agent",
		Description: schema.MultiLine("Custom user agent string for the headless request"),
		Example:     schema.PropertyExample("Mozilla/5.0 (compatible; Nuclei)"),
	},
	{
		PropName: "payloads",
		Description: schema.MultiLine("Payloads for the headless request"),
	},
	{
		PropName: "attack",
		Description: schema.MultiLine(
			"Payload combination strategy when payloads are defined",
			"Supported values: batteringram, pitchfork, clusterbomb",
		),
		Example: schema.PropertyExamples("batteringram", "pitchfork", "clusterbomb"),
	},
	{
		PropName: "fuzzing",
		Description: schema.MultiLine("Fuzzing/DAST rules that mutate headless requests"),
	},
	{
		PropName: "stop-at-first-match",
		Description: schema.MultiLine("Stop execution after the first match is found"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "cookie-reuse",
		Description: schema.MultiLine(
			"Deprecated: cookie reuse is the default behaviour; use disable-cookie to disable it",
		),
		Deprecated: true,
	},
	{
		PropName: "disable-cookie",
		Description: schema.MultiLine("Disable cookie reuse for this headless request"),
		Example:     schema.PropertyExample(true),
	},
}

var headlessRequestAnyOfRequired = []schema.RequiredCombos{
	schema.Require("steps"),
}

// JSONSchemaExtend extends the headless request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(headlessRequestMetadata, base)
	schema.ApplyAnyOfRequired(headlessRequestAnyOfRequired, base)
}
