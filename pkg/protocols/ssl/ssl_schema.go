package ssl

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var sslRequestMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine("Optional ID of this SSL request block"),
		Example:     schema.PropertyExample("ssl-cert"),
	},
	{
		PropName: "address",
		Description: schema.MultiLine(
			"Address for the SSL request",
			"Example:",
			"```yaml",
			"address: \"{{Host}}:{{Port}}\"",
			"```",
		),
		Example: schema.PropertyExamples("{{Host}}:{{Port}}", "{{Hostname}}"),
	},
	{
		PropName: "min_version",
		Description: schema.MultiLine(
			"Minimum TLS version",
			"Supported values: sslv3, tls10, tls11, tls12, tls13",
		),
		Example: schema.PropertyExamples("tls12", "tls13"),
	},
	{
		PropName: "max_version",
		Description: schema.MultiLine(
			"Maximum TLS version",
			"Supported values: sslv3, tls10, tls11, tls12, tls13",
		),
		Example: schema.PropertyExamples("tls12", "tls13"),
	},
	{
		PropName: "cipher_suites",
		Description: schema.MultiLine("Explicit cipher suites to negotiate"),
	},
	{
		PropName: "scan_mode",
		Description: schema.MultiLine(
			"Scan mode for SSL enumeration",
			"Supported values: ctls, ztls, auto",
		),
		Example: schema.PropertyExamples("auto", "ctls", "ztls"),
		Default: "auto",
	},
	{
		PropName: "tls_version_enum",
		Description: schema.MultiLine("Enumerate supported TLS versions"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "tls_cipher_enum",
		Description: schema.MultiLine("Enumerate supported TLS ciphers"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "tls_cipher_types",
		Description: schema.MultiLine(
			"TLS cipher types to enumerate",
			"Supported values: weak, secure, insecure, all",
		),
		Example: schema.PropertyExamples("weak", "secure", "all"),
	},
}

var sslRequestAnyOfRequired = []schema.RequiredCombos{
	schema.Require("address"),
}

// JSONSchemaExtend extends the SSL request JSON schema.
func (Request) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(sslRequestMetadata, base)
	schema.ApplyAnyOfRequired(sslRequestAnyOfRequired, base)
}
