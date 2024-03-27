package templates

import "github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"

// contains metadata information about template
var templateMetadata = []schema.PropertyMetadata{
	{
		PropName: "id",
		PropType: "string",
		Description: schema.MultiLine(
			"ID is the unique id for the template.",
			" ### Good IDs ",
			"A good ID uniquely identifies what the requests in the template",
			"are doing. Let's say you have a template that identifies a git-config",
			"file on the webservers, a good name would be `git-config-exposure`. Another",
			"example name is `azure-apps-nxdomain-takeover`",
		),
		Example: schema.PropertyExamples("example-id", "git-config-exposure", "azure-apps-nxdomain-takeover", "cve-2021-19520"),
	},
	{
		PropName: "flow",
		PropType: "string",
		Description: schema.MultiLine(
			"Flow describes how multiple request-blocks/protocols should be combined together and executed",
			"It is a javascript code where each protocol is a function and all request-blocks are indexed by their corresponding index in request array",
			"Example: ",
			" flow: http(1) && http(2)",
			" means that second http request will be executed only if first http request is successful (aka matched)",
		),
		Example: schema.PropertyExamples(
			"http(1) && http(2)",
			schema.MultiLine(
				" | # example-vhost-enum",
				"\tssl(); // ->  execute all ssl protocol requests",
				"\tdns(); // ->  execute all dns protocol requests",
				"\tfor (let got of template.domains) { // ->  iterate over 'domains' array variable",
				"\t\tset('vhost', got); // ->  set 'vhost' variable to current domain",
				"\t\thttp(); // ->  execute all http protocol requests",
				"\t}\n",
			),
		),
	},
	{
		PropName:   "requests",
		Deprecated: true,
	},
	{
		PropName:   "network",
		Deprecated: true,
	},
	{
		PropName:   "signature",
		Deprecated: true,
	},
	{
		PropName: "self-contained",
		Description: schema.MultiLine(
			"Self-contained marks all requests in this template as independent of input which means input/target is not required for execution of template",
			"but other variables defined in template need to be explicitly set using -V flag",
			"Default value is false",
			"Note: self-contained templates only run once regardless of how many targets where provided to nuclei",
			"Example: ",
			"```yaml",
			"self-contained: true",
			"```",
			"Full example template of self-contained is available at https://cloud.projectdiscovery.io/public/aws-app-enum",
		),
		Default: false,
		Example: schema.PropertyExample(true),
	},
	{
		PropName: "info",
		Description: schema.MultiLine(
			"Info contains the required metadata information about the template",
			"It is meant to provide basic but necessary info like name, author , severity",
			"along with many other optional fields like metadata, classification etc",
			"Note: - ",
			"For a template to be valid name,author,severity of `info` section must be set",
		),
	},
	{
		PropName: "stop-at-first-match",
		Description: schema.MultiLine(
			"stop-at-first-match stops the execution of template as soon as first match/result was found in a template given that template was sending multiple requests",
			"this is required in case of default-login , brute-force and even detection templates where multiple requests are sent from template but we want to exit as soon as first match/result was found",
			"Example: ",
			"```yaml",
			"stop-at-first-match: true",
			"```",
			"Full example template of stop-at-first-match is available at https://cloud.projectdiscovery.io/public/bitbucket-public-repository",
		),
		Default: false,
		Example: schema.PropertyExample(true),
	},
	{
		PropName:  "variables",
		PropType:  "object",
		RemoveRef: true,
		Description: schema.MultiLine(
			"Variables are the global variables that once defined here can be used anywhere in the template",
			"Variables are evaluated in the order they are defined so one variable can be referenced in another variable",
			"Variables are evaluated before sending every requests so one can reference any variables that are available at runtime and they will be evaluate and used when referenced",
			"Example: ",
			"```yaml",
			"variables:",
			`  oast: {{interact-sh}}`,
			`  payload: "{{base64(oast)}}"`,
			"```",
			"Full example template of variables is available at https://cloud.projectdiscovery.io/public/screenshot",
			"Note: -",
			"These variables can be overridden by -V flag at runtime if needed",
		),
		Example: schema.PropertyExamples(
			schema.MultiLine(
				"\n\tdomain: \"{{FQDN}}\"",
				"\temail: pdteam@{{domain}}",
			),
			schema.MultiLine(
				"\n\toast: \"{{interact-sh}}\"",
				"\tpayload: \"{{base64(oast)}}\"",
			),
		),
	},
	{
		PropName:  "constants",
		PropType:  "object",
		RemoveRef: true,
		Description: schema.MultiLine(
			"Constants are the global constants that once defined here can be used anywhere in the template",
			"It can be used in same way as variables but only difference is that constants cannot be overridden by -V flag at runtime",
			"Example: ",
			"```yaml",
			"constants:",
			`  exploit: 'x0x0x0x0x0x0x`,
			"```",
		),
		Example: schema.PropertyExample(
			schema.MultiLine(
				"\n\texploit: 'x0x0x0x0x0x0x",
			),
		),
	},
}

// valid template should contain at least on below combinations
// requireBase uses two arguments to generate all combinations in format of
// base_[0]
// base_[1] etc
var templateAnyOfRequired = []schema.RequiredCombos{
	schema.RequireBase([]string{"id", "info"},
		schema.Require("http"),
		schema.Require("dns"),
		schema.Require("file"),
		schema.Require("tcp"),
		schema.Require("headless"),
		schema.Require("ssl"),
		schema.Require("websocket"),
		schema.Require("whois"),
		schema.Require("code"),
		schema.Require("javascript"),
		schema.Require("requests"),
		schema.Require("network"),
	),
	schema.Require("workflows"),
}

// contains examples for template
var templateExamples = schema.PropertyExamples()
