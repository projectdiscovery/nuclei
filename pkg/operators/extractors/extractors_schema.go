package extractors

import (
	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

var extractorMetadata = []schema.PropertyMetadata{
	{
		PropName: "name",
		Description: schema.MultiLine(
			"Optional extractor name used as a variable key",
			"Prefer lowercase without spaces or underscores",
		),
		Example: schema.PropertyExample("cookie-extractor"),
	},
	{
		PropName: "type",
		Description: schema.MultiLine(
			"Type of the extractor",
			"Supported values: regex, kval, json, xpath, dsl",
		),
		Example: schema.PropertyExamples("regex", "kval", "json", "xpath", "dsl"),
	},
	{
		PropName: "regex",
		Description: schema.MultiLine("Regular expression patterns used to extract values"),
		Example:     schema.PropertyExample([]string{`token=([a-z0-9]+)`}),
	},
	{
		PropName: "group",
		Description: schema.MultiLine("Numbered capture group to extract from the regex"),
		Example:     schema.PropertyExample(1),
	},
	{
		PropName: "kval",
		Description: schema.MultiLine(
			"Key names to extract from headers/cookies (case-insensitive)",
			"Dashes in header names must be replaced with underscores",
		),
		Example: schema.PropertyExamples([]string{"server"}, []string{"content_type"}),
	},
	{
		PropName: "json",
		Description: schema.MultiLine("jq-style expressions used to extract from JSON responses"),
		Example:     schema.PropertyExample([]string{".[] | .id"}),
	},
	{
		PropName: "xpath",
		Description: schema.MultiLine("XPath expressions used to extract from HTML responses"),
		Example:     schema.PropertyExample([]string{"/html/body/div/p[2]/a"}),
	},
	{
		PropName: "attribute",
		Description: schema.MultiLine("Optional HTML attribute to extract from XPath matches"),
		Example:     schema.PropertyExample("href"),
	},
	{
		PropName: "dsl",
		Description: schema.MultiLine("DSL expressions used to extract values"),
		Example:     schema.PropertyExample([]string{"body"}),
	},
	{
		PropName: "part",
		Description: schema.MultiLine(
			"Part of the protocol response to extract from",
			"Common values: body, header, all, raw",
		),
		Example: schema.PropertyExamples("body", "header", "all"),
	},
	{
		PropName: "internal",
		Description: schema.MultiLine("Mark extracted value for internal use in subsequent requests"),
		Example:     schema.PropertyExample(true),
	},
	{
		PropName: "case-insensitive",
		Description: schema.MultiLine("Perform case-insensitive extraction when supported"),
		Example:     schema.PropertyExample(true),
	},
}

var extractorAnyOfRequired = []schema.RequiredCombos{
	schema.Require("type", "regex"),
	schema.Require("type", "kval"),
	schema.Require("type", "json"),
	schema.Require("type", "xpath"),
	schema.Require("type", "dsl"),
}

// JSONSchemaExtend extends the Extractor JSON schema.
func (Extractor) JSONSchemaExtend(base *jsonschema.Schema) {
	schema.ExtendSchema(extractorMetadata, base)
	schema.ApplyAnyOfRequired(extractorAnyOfRequired, base)
}
