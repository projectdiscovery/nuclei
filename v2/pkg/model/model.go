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
	//   - value: "\"Bower is a package manager which stores packages information in bower.json file\""
	//   - value: "\"Subversion ALM for the enterprise before 8.8.2 allows reflected XSS at multiple locations\""
	Description string `json:"description,omitempty" yaml:"description,omitempty" jsonschema:"title=description of the template,description=In-depth explanation on what the template does,example=Bower is a package manager which stores packages informations in bower.json file"`
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
	//
	// values:
	//   - info
	//   - low
	//   - medium
	//   - high
	//   - critical
	SeverityHolder severity.Holder `json:"severity,omitempty" yaml:"severity,omitempty"`
	// description: |
	//   AdditionalFields regarding metadata of the template.
	//
	// examples:
	//   - value: >
	//       map[string]string{"customField1":"customValue1"}
	AdditionalFields map[string]string `json:"additional-fields,omitempty" yaml:"additional-fields,omitempty" jsonschema:"title=additional metadata for the template,description=Additional metadata fields for the template"`
}
