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
	finalInput := input

	// Apply text templating if enabled
	if j.opts.VarsTextTemplating {
		data, err := io.ReadAll(input)
		if err != nil {
			return errors.Wrap(err, "could not read input")
		}
		tpl := []string{string(data)}
		dvs := mapToKeyValueSlice(j.opts.Variables)
		finalInput, err = ytt(tpl, dvs, j.opts.VarsFilePaths)
		if err != nil {
			return errors.Wrap(err, "could not apply ytt templating")
		}
		finalData, err := io.ReadAll(finalInput)
		if err != nil {
			return errors.Wrap(err, "could not read templated input")
		}
		finalInput = strings.NewReader(string(finalData))

	}

	decoder := YamlUtil.NewDecoder(finalInput)
	for {
		var request proxifyRequest
		if err := decoder.Decode(&request); err != nil {
			if err == io.EOF {
				break
			}
			return errors.Wrap(err, "could not decode yaml file")
		}

		raw := strings.TrimSpace(request.Request.Raw)
		if raw == "" {
			continue
		}

		rawRequest, err := types.ParseRawRequestWithURL(raw, request.URL)
		if err != nil {
			gologger.Warning().Msgf("multidoc-yaml: Could not parse raw request %s: %s", request.URL, err)
			continue
		}
		resultsCb(rawRequest)
	}
	return nil
}
