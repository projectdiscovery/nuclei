package model

import (
	"slices"
	"strings"

	"github.com/invopop/jsonschema"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/marker"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/schema"
)

// Info contains metadata information about a template
type Info struct {
	// description: |
	//   Name should be good short summary that identifies what the template does.
	//
	// examples:
	//   - value: "\"bower.json file disclosure\""
	//   - value: "\"Nagios Default Credentials Check\""
	Name string `json:"name,omitempty" yaml:"name,omitempty" jsonschema:"title=name of the template,description=Name is a short summary of what the template does,type=string,required,example=Nagios Default Credentials Check"`
	// description: |
	//   Author of the template.
	//
	//   Multiple values can also be specified separated by commas.
	// examples:
	//   - value: "\"<username>\""
	Authors stringslice.StringSlice `json:"author,omitempty" yaml:"author,omitempty" jsonschema:"title=author of the template,description=Author is the author of the template,required,example=username"`
	// description: |
	//   Any tags for the template.
	//
	//   Multiple values can also be specified separated by commas.
	//
	// examples:
	//   - name: Example tags
	//     value: "\"cve,cve2019,grafana,auth-bypass,dos\""
	Tags stringslice.StringSlice `json:"tags,omitempty" yaml:"tags,omitempty" jsonschema:"title=tags of the template,description=Any tags for the template"`
	// description: |
	//   Description of the template.
	//
	//   You can go in-depth here on what the template actually does.
	//
	//   Description, impact and remediation may hold {{placeholders}} filled for
	//   each finding: named extractors, payloads, variables and DSL helpers
	//   (network helpers excluded), and the result fields host, port, ip, url,
	//   scheme, path, matched-at, matcher-name and extractor-name, which win over
	//   values of the same name. Use join(", ", name) for an extractor with
	//   several values, and brackets for a hyphenated name inside a helper:
	//   to_upper([matcher-name]). Unknown placeholders stay as written, and so
	//   does a field whose expression fails. Global matcher templates match on
	//   other templates' responses, so only the result fields fill their text.
	//
	// examples:
	//   - value: "\"Bower is a package manager which stores package information in the bower.json file\""
	//   - value: "\"Subversion ALM for the enterprise before 8.8.2 allows reflected XSS at multiple locations\""
	//   - value: "\"Redis {{version}} on {{host}}:{{port}} accepts the default password\""
	Description string `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"title=description of the template,description=In-depth explanation on what the template does,type=string,example=Bower is a package manager which stores package information in the bower.json file"`
	// description: |
	//   Impact of the template.
	//
	//   You can go in-depth here on impact of the template.
	//
	//   Supports the same placeholders as description.
	//
	// examples:
	//   - value: "\"Successful exploitation of this vulnerability could allow an attacker to execute arbitrary SQL queries, potentially leading to unauthorized access, data leakage, or data manipulation.\""
	//   - value: "\"Successful exploitation of this vulnerability could allow an attacker to execute arbitrary script code in the context of the victim's browser, potentially leading to session hijacking, defacement, or theft of sensitive information.\""
	Impact string `json:"impact,omitempty" yaml:"impact,omitempty" jsonschema:"title=impact of the template,description=In-depth explanation on the impact of the issue found by the template,example=Successful exploitation of this vulnerability could allow an attacker to execute arbitrary SQL queries, potentially leading to unauthorized access, data leakage, or data manipulation.,type=string"`
	// description: |
	//   References for the template.
	//
	//   This should contain links relevant to the template.
	//
	// examples:
	//   - value: >
	//       []string{"https://github.com/strapi/strapi", "https://github.com/getgrav/grav"}
	Reference *stringslice.RawStringSlice `json:"reference,omitempty" yaml:"reference,omitempty" jsonschema:"title=references for the template,description=Links relevant to the template"`
	// description: |
	//   Severity of the template.
	SeverityHolder severity.Holder `json:"severity,omitempty" yaml:"severity,omitempty"`
	// description: |
	//   Metadata of the template.
	//
	// examples:
	//   - value: >
	//       map[string]string{"customField1":"customValue1"}
	Metadata map[string]interface{} `json:"metadata,omitempty" yaml:"metadata,omitempty" jsonschema:"title=additional metadata for the template,description=Additional metadata fields for the template,type=object"`

	// description: |
	//   Classification contains classification information about the template.
	Classification *Classification `json:"classification,omitempty" yaml:"classification,omitempty" jsonschema:"title=classification info for the template,description=Classification information for the template,type=object"`

	// description: |
	//   Remediation steps for the template.
	//
	//   You can go in-depth here on how to mitigate the problem found by this template.
	//
	//   Supports the same placeholders as description.
	//
	// examples:
	//   - value: "\"Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties\""
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty" jsonschema:"title=remediation steps for the template,description=In-depth explanation on how to fix the issues found by the template,example=Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties,type=string"`
}

// TextField is a free-text field of the info, labeled as reports show it.
type TextField struct {
	Label string
	Value *string
}

// PlaceholderFields returns the free-text fields that may hold {{placeholders}}
// filled for each finding. Rendering, redaction and the sarif export all walk
// this one list, so a field added here is handled by every one of them.
func (i *Info) PlaceholderFields() []TextField {
	return []TextField{
		{Label: "Description", Value: &i.Description},
		{Label: "Impact", Value: &i.Impact},
		{Label: "Remediation", Value: &i.Remediation},
	}
}

// HasPlaceholders reports whether the field holds a {{...}} or §...§ marker
// the renderer could fill.
func (f TextField) HasPlaceholders() bool {
	return strings.Contains(*f.Value, marker.ParenthesisOpen) || strings.Contains(*f.Value, marker.General)
}

// HasPlaceholders reports whether any placeholder field holds a marker.
func (i *Info) HasPlaceholders() bool {
	return slices.ContainsFunc(i.PlaceholderFields(), TextField.HasPlaceholders)
}

// FilledFields returns the placeholder fields whose text differs from written,
// the info as the template wrote it. A nil written means nothing was filled.
func (i *Info) FilledFields(written *Info) []TextField {
	if written == nil {
		return nil
	}
	writtenFields := written.PlaceholderFields()
	var filled []TextField
	for n, field := range i.PlaceholderFields() {
		if *field.Value != *writtenFields[n].Value {
			filled = append(filled, field)
		}
	}
	return filled
}

// JSONSchemaExtend extends the Info JSON schema with richer descriptions and examples.
func (i Info) JSONSchemaExtend(base *jsonschema.Schema) {
	base.Examples = infoSectionExamples
	schema.ExtendSchema(infoSectionMetadata, base)
}

// Classification contains the vulnerability classification data for a template.
type Classification struct {
	// description: |
	//   CVE ID for the template
	// examples:
	//   - value: "\"CVE-2020-14420\""
	CVEID stringslice.StringSlice `json:"cve-id,omitempty" yaml:"cve-id,omitempty" jsonschema:"title=cve ids for the template,description=CVE IDs for the template,example=CVE-2020-14420"`
	// description: |
	//   CWE ID for the template.
	// examples:
	//   - value: "\"CWE-22\""
	CWEID stringslice.StringSlice `json:"cwe-id,omitempty" yaml:"cwe-id,omitempty" jsonschema:"title=cwe ids for the template,description=CWE IDs for the template,example=CWE-22"`
	// description: |
	//   CVSS Metrics for the template.
	// examples:
	//   - value: "\"3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\""
	CVSSMetrics string `json:"cvss-metrics,omitempty" yaml:"cvss-metrics,omitempty" jsonschema:"title=cvss metrics for the template,description=CVSS Metrics for the template,example=3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"`
	// description: |
	//   CVSS Score for the template.
	// examples:
	//   - value: "\"9.8\""
	CVSSScore float64 `json:"cvss-score,omitempty" yaml:"cvss-score,omitempty" jsonschema:"title=cvss score for the template,description=CVSS Score for the template,example=9.8"`
	// description: |
	//   EPSS Score for the template.
	// examples:
	//   - value: "\"0.42509\""
	EPSSScore float64 `json:"epss-score,omitempty" yaml:"epss-score,omitempty" jsonschema:"title=epss score for the template,description=EPSS Score for the template,example=0.42509"`
	// description: |
	//   EPSS Percentile for the template.
	// examples:
	//   - value: "\"0.42509\""
	EPSSPercentile float64 `json:"epss-percentile,omitempty" yaml:"epss-percentile,omitempty" jsonschema:"title=epss percentile for the template,description=EPSS Percentile for the template,example=0.42509"`
	// description: |
	//   CPE for the template.
	// examples:
	//   - value: "\"cpe:/a:vendor:product:version\""
	CPE string `json:"cpe,omitempty" yaml:"cpe,omitempty" jsonschema:"title=cpe for the template,description=CPE for the template,example=cpe:/a:vendor:product:version"`
}
