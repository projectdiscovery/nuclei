package model

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
)

// Info contains metadata information about a template
type Info struct {
	// description: |
	//   Name should be good short summary that identifies what the template does.
	//
	// examples:
	//   - value: "\"bower.json file disclosure\""
	//   - value: "\"Nagios Default Credentials Check\""
	Name string `json:"name,omitempty" yaml:"name,omitempty" jsonschema:"title=name of the template,description=Name is a short summary of what the template does,example=Nagios Default Credentials Check"`
	// description: |
	//   Author of the template.
	//
	//   Multiple values can also be specified separated by commas.
	// examples:
	//   - value: "\"<username>\""
	Authors stringslice.StringSlice `json:"author,omitempty" yaml:"author,omitempty" jsonschema:"title=author of the template,description=Author is the author of the template,example=username"`
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
	// examples:
	//   - value: "\"Bower is a package manager which stores package information in the bower.json file\""
	//   - value: "\"Subversion ALM for the enterprise before 8.8.2 allows reflected XSS at multiple locations\""
	Description string `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"title=description of the template,description=In-depth explanation on what the template does,example=Bower is a package manager which stores package information in the bower.json file"`
	// description: |
	//   References for the template.
	//
	//   This should contain links relevant to the template.
	//
	// examples:
	//   - value: >
	//       []string{"https://github.com/strapi/strapi", "https://github.com/getgrav/grav"}
	Reference stringslice.StringSlice `json:"reference,omitempty" yaml:"reference,omitempty" jsonschema:"title=references for the template,description=Links relevant to the template"`
	// description: |
	//   Severity of the template.
	SeverityHolder severity.Holder `json:"severity,omitempty" yaml:"severity,omitempty"`
	// description: |
	//   Metadata of the template.
	//
	// examples:
	//   - value: >
	//       map[string]string{"customField1":"customValue1"}
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty" jsonschema:"title=additional metadata for the template,description=Additional metadata fields for the template"`

	// description: |
	//   Classification contains classification information about the template.
	Classification *Classification `json:"classification,omitempty" yaml:"classification,omitempty" jsonschema:"title=classification info for the template,description=Classification information for the template"`

	// description: |
	//   Remediation steps for the template.
	//
	//   You can go in-depth here on how to mitigate the problem found by this template.
	//
	// examples:
	//   - value: "\"Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties\""
	Remediation string `json:"remediation,omitempty" yaml:"remediation,omitempty" jsonschema:"title=remediation steps for the template,description=In-depth explanation on how to fix the issues found by the template,example=Change the default administrative username and password of Apache ActiveMQ by editing the file jetty-realm.properties"`
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
}
