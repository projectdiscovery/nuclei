package network

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var networkRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine(
			"Optional ID of this TCP/network request block",
			"Useful when calling / executing this request block from flow",
		),
		Example: schema.PropertyExample("tcp-banner"),
	},
	{
		PropName: "host",
		Description: schema.MultiLine(
			"Host(s) to send network requests to",
			"Supports network helpers like `tls://` and port suffixes",
			"Example:",
			"```yaml",
			"host:",
			"  - \"{{Hostname}}\"",
			"  - \"tls://{{Hostname}}\"",
			"```",
		),
		Example: schema.PropertyExamples("{{Hostname}}", "tls://{{Hostname}}"),
	},
	{
		PropName: "port",
		Description: schema.MultiLine(
			"Port to send network requests to",
			"Supports numeric ports and service names (ftp, ssh, smtp)",
		),
		Example: schema.PropertyExamples("80", "443", "ssh"),
	},
	{
		PropName: "exclude-ports",
		Description: schema.MultiLine("Ports to exclude from being scanned"),
		Example:     schema.PropertyExample("22,25"),
	},
	{
		PropName: "inputs",
		Description: schema.MultiLine(
			"Input/output steps for the network request",
			"Example:",
			"```yaml",
			"inputs:",
			"  - data: \"HELP\\r\\n\"",
			"    read: 1024",
			"```",
		),
	},
	{
		PropName: "read-size",
		Description: schema.MultiLine("Size of response to read at the end. Default is 1024 bytes"),
		Example:     schema.PropertyExample(1024),
		Default:     1024,
	},
	{
		PropName: "read-all",
		Description: schema.MultiLine("Read the entire response stream until the server stops sending"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "stop-at-first-match",
		Description: schema.MultiLine("Stop execution after the first match is found"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "payloads",
		Description: schema.MultiLine("Payloads for the network request"),
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
		Description: schema.MultiLine("Concurrency for sending network requests with payloads"),
		Example:     schema.PropertyExample(10),
	},
}

var networkRequestAnyOfRequired = []schema.RequiredCombos{
	schema.Require("host"),
	schema.Require("inputs"),
}

// JSONSchemaExtend extends the network/TCP request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(networkRequestMetadata, base)
	schema.ApplyAnyOfRequired(networkRequestAnyOfRequired, base)
}
