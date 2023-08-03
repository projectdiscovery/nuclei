package offlinehttp

import (
	"github.com/pkg/errors"

	"github.com/projectdiscovery/nuclei/v2/pkg/operators"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
)

// Request is a offline http response processing request
type Request struct {
	options           *protocols.ExecutorOptions
	compiledOperators []*operators.Operators
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"template-id":           "ID of the template executed",
	"template-info":         "Info Block of the template executed",
	"template-path":         "Path of the template executed",
	"host":                  "Host is the input to the template",
	"matched":               "Matched is the input which was matched upon",
	"type":                  "Type is the type of request made",
	"request":               "HTTP request made from the client",
	"response":              "HTTP response received from server",
	"status_code":           "Status Code received from the Server",
	"body":                  "HTTP response body received from server (default)",
	"content_length":        "HTTP Response content length",
	"header,all_headers":    "HTTP response headers",
	"duration":              "HTTP request time duration",
	"all":                   "HTTP response body + headers",
	"cookies_from_response": "HTTP response cookies in name:value format",
	"headers_from_response": "HTTP response headers in name:value format",
}

// GetID returns the unique ID of the request if any.
func (request *Request) GetID() string {
	return ""
}

// Compile compiles the protocol request for further execution.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	for _, operator := range options.Operators {
		if err := operator.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		request.compiledOperators = append(request.compiledOperators, operator)
	}
	request.options = options
	return nil
}

// Requests returns the total number of requests the YAML rule will perform
func (request *Request) Requests() int {
	return 1
}
