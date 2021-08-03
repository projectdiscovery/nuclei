package templates

import (
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/dns"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/file"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/network"
	"github.com/projectdiscovery/nuclei/v2/pkg/workflows"
)

// nolint:deadcode // this is intentional
var (
	exampleTomcatUserPassPayload = map[string]interface{}{
		"username": []string{"tomcat", "admin"},
		"password": []string{"tomcat", "admin", "password"},
	}
	exampleFileBasedPayload = map[string]interface{}{
		"data": "helpers/payloads/command-injection.txt",
	}
)

// Template is a YAML input file which defines the requests and
// others metadata for a scan template.
type Template struct {
	// description: |
	//   ID is the unique id for the template. IDs must be lowercase
	//   and must not contain spaces in it.
	//
	//   #### Good IDs
	//
	//   A good ID uniquely identifies what the requests in the template
	//   are doing. Let's say you have a template that identifies a git-config
	//   file on the webservers, a good name would be `git-config-exposure`. Another
	//   example name is `azure-apps-nxdomain-takeover`.
	// examples:
	//   - name: ID Example
	//     value: "\"cve-2021-19520\""
	ID string `yaml:"id"`
	// description: |
	//   Info contains metadata information about the template. At minimum, it
	//   should contain `name`, `author`, `severity`, `description`, `tags`. Optionally
	//   you can also specify a list of `references` for the template.
	Info map[string]interface{} `yaml:"info"`
	// description: |
	//   Requests contains the http request to make in the template
	RequestsHTTP []*http.Request `yaml:"requests,omitempty" json:"requests"`
	// description: |
	//   DNS contains the dns request to make in the template
	RequestsDNS []*dns.Request `yaml:"dns,omitempty" json:"dns"`
	// description: |
	//   File contains the file request to make in the template
	RequestsFile []*file.Request `yaml:"file,omitempty" json:"file"`
	// description: |
	//   Network contains the network request to make in the template
	RequestsNetwork []*network.Request `yaml:"network,omitempty" json:"network"`
	// description: |
	//   Headless contains the headless request to make in the template.
	RequestsHeadless []*headless.Request `yaml:"headless,omitempty" json:"headless"`

	// description: |
	//   Workflows is a yaml based workflow declaration code.
	workflows.Workflow `yaml:",inline,omitempty"`
	CompiledWorkflow   *workflows.Workflow `yaml:"-" json:"-" jsonschema:"-"`

	// TotalRequests is the total number of requests for the template.
	TotalRequests int `yaml:"-" json:"-"`
	// Executer is the actual template executor for running template requests
	Executer protocols.Executer `yaml:"-" json:"-"`

	Path string `yaml:"-" json:"-"`
}
