package yaml

import (
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	YamlUtil "gopkg.in/yaml.v3"
)

// YamlMultiDocFormat is a Yaml format parser for nuclei
// input HTTP requests with multiple documents separated by ---
type YamlMultiDocFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new JSON format parser
func New() *YamlMultiDocFormat {
	return &YamlMultiDocFormat{}
}

var _ formats.Format = &YamlMultiDocFormat{}

// proxifyRequest is a request for proxify
type proxifyRequest struct {
	URL     string `json:"url"`
	Request struct {
		Header map[string]string `json:"header"`
		Body   string            `json:"body"`
		Raw    string            `json:"raw"`
	} `json:"request"`
}

// Name returns the name of the format
func (j *YamlMultiDocFormat) Name() string {
	return "yaml"
}

func (j *YamlMultiDocFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *YamlMultiDocFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	decoder := YamlUtil.NewDecoder(input)
	for {
		var request proxifyRequest
		err := decoder.Decode(&request)
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "could not decode json file")
		}
		if strings.TrimSpace(request.Request.Raw) == "" {
			continue
		}

		rawRequest, err := types.ParseRawRequestWithURL(request.Request.Raw, request.URL)
		if err != nil {
			gologger.Warning().Msgf("multidoc-yaml: Could not parse raw request %s: %s\n", request.URL, err)
			continue
		}
		resultsCb(rawRequest)
	}
	return nil
}
