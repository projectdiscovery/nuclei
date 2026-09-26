package matchers

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var matcherMetadata = []schema.PropertyMetadata{
	{
		PropName: "type",
		Description: schema.MultiLine(
			"Type of the matcher",
			"Supported values: status, size, word, regex, binary, dsl, xpath",
		),
		Example: schema.PropertyExamples("status", "word", "regex", "dsl"),
	},
	{
		PropName: "condition",
		Description: schema.MultiLine(
			"Condition between matcher values (default: or)",
			"Supported values: and, or",
		),
		Example: schema.PropertyExamples("and", "or"),
		Default: "or",
	},
	{
		PropName: "part",
		Description: schema.MultiLine(
			"Part of the protocol response to match against",
			"Common values: body, header, all, raw (protocol-specific parts also exist)",
		),
		Example: schema.PropertyExamples("body", "header", "all", "raw"),
	},
	{
		PropName: "negative",
		Description: schema.MultiLine("Reverse the match; only matches when the condition is not true"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "name",
		Description: schema.MultiLine(
			"Optional matcher name used for named matching / workflows",
			"Prefer lowercase without spaces or underscores",
		),
		Example: schema.PropertyExample("cookie-matcher"),
	},
	{
		PropName: "status",
		Description: schema.MultiLine("Acceptable HTTP status codes (status matcher)"),
		Example:     schema.PropertyExample([]int{200, 302}),
	},
	{
		PropName: "size",
		Description: schema.MultiLine("Acceptable response sizes (size matcher)"),
		Example:     schema.PropertyExample([]int{1024, 2048}),
	},
	{
		PropName: "words",
		Description: schema.MultiLine("Word patterns that must be present (word matcher)"),
		Example:     schema.PropertyExample([]string{"application/json"}),
	},
	{
		PropName: "regex",
		Description: schema.MultiLine("Regular expressions that must match (regex matcher)"),
		Example:     schema.PropertyExample([]string{`(?i)admin`}),
	},
	{
		PropName: "binary",
		Description: schema.MultiLine("Hex binary patterns that must be present (binary matcher)"),
		Example:     schema.PropertyExample([]string{"1f8b080000000000"}),
	},
	{
		PropName: "dsl",
		Description: schema.MultiLine("DSL expressions that must evaluate to true (dsl matcher)"),
		Example:     schema.PropertyExample([]string{"status_code == 200", "contains(body, 'ok')"}),
	},
	{
		PropName: "xpath",
		Description: schema.MultiLine("XPath expressions that must match (xpath matcher)"),
	},
	{
		PropName: "case-insensitive",
		Description: schema.MultiLine("Perform case-insensitive matching when supported"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "match-all",
		Description: schema.MultiLine("Require all values to match instead of any"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "internal",
		Description: schema.MultiLine("Mark matcher as internal (used for flow / internal logic)"),
		Example:     schema.PropertyExample(true),
	},
}

var matcherAnyOfRequired = []schema.RequiredCombos{
	schema.Require("type", "status"),
	schema.Require("type", "size"),
	schema.Require("type", "words"),
	schema.Require("type", "regex"),
	schema.Require("type", "binary"),
	schema.Require("type", "dsl"),
	schema.Require("type", "xpath"),
}

// JSONSchemaExtend extends the Matcher JSON schema.
func (Matcher) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(matcherMetadata, base)
	schema.ApplyAnyOfRequired(matcherAnyOfRequired, base)
}
