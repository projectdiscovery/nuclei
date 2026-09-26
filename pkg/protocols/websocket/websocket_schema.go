package websocket

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var websocketRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine("Optional ID of this websocket request block"),
		Example:     schema.PropertyExample("ws-echo"),
	},
	{
		PropName: "address",
		Description: schema.MultiLine(
			"Websocket address for the request",
			"Example:",
			"```yaml",
			"address: \"{{Hostname}}\"",
			"```",
		),
		Example: schema.PropertyExample("{{Hostname}}"),
	},
	{
		PropName: "inputs",
		Description: schema.MultiLine(
			"Input messages to send over the websocket",
			"Example:",
			"```yaml",
			"inputs:",
			"  - data: \"ping\"",
			"    name: ping",
			"```",
		),
	},
	{
		PropName: "headers",
		Description: schema.MultiLine("Headers for the websocket handshake request"),
		Example: schema.PropertyExample(map[string]string{
			"Origin": "https://example.com",
		}),
	},
	{
		PropName: "payloads",
		Description: schema.MultiLine("Payloads for the websocket request"),
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

var websocketRequestAnyOfRequired = []schema.RequiredCombos{
	schema.Require("address"),
}

// JSONSchemaExtend extends the websocket request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(websocketRequestMetadata, base)
	schema.ApplyAnyOfRequired(websocketRequestAnyOfRequired, base)
}
