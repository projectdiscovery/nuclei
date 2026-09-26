package javascript

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var javascriptRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine("Optional ID of this javascript request block"),
		Example:     schema.PropertyExample("js-probe"),
	},
	{
		PropName: "code",
		Description: schema.MultiLine(
			"Inline JavaScript code executed for the request",
			"Example:",
			"```yaml",
			"code: |",
			"  let m = require('nuclei/net');",
			"  Export(m.OpenTCP(Host, Port));",
			"```",
		),
	},
	{
		PropName: "init",
		Description: schema.MultiLine(
			"JavaScript code executed after compiling the template (before request execution)",
		),
	},
	{
		PropName: "args",
		Description: schema.MultiLine(
			"Arguments exposed to the JavaScript runtime",
			"Example:",
			"```yaml",
			"args:",
			"  Host: \"{{Host}}\"",
			"  Port: \"443\"",
			"```",
		),
	},
	{
		PropName: "pre-condition",
		Description: schema.MultiLine(
			"JavaScript condition evaluated before executing the request",
		),
		Example: schema.PropertyExample("Port == 443"),
	},
	{
		PropName: "payloads",
		Description: schema.MultiLine("Payloads for the javascript request"),
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
		PropName: "threads",
		Description: schema.MultiLine("Concurrency for sending javascript requests with payloads"),
		Example:     schema.PropertyExample(10),
	},
	{
		PropName: "stop-at-first-match",
		Description: schema.MultiLine("Stop execution after the first match is found"),
		Example:     schema.PropertyExample(true),
	},
}

var javascriptRequestAnyOfRequired = []schema.RequiredCombos{
	schema.Require("code"),
}

// JSONSchemaExtend extends the javascript request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(javascriptRequestMetadata, base)
	schema.ApplyAnyOfRequired(javascriptRequestAnyOfRequired, base)
}
