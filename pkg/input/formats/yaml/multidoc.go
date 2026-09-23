package yaml

import (
	"bytes"
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
	URL     string `json:"url" yaml:"url"`
	Request struct {
		Header map[string]string `json:"header" yaml:"header"`
		Body   string            `json:"body" yaml:"body"`
		Raw    string            `json:"raw" yaml:"raw"`
	} `json:"request" yaml:"request"`
	Response *proxifyResponse `json:"response,omitempty" yaml:"response,omitempty"`
}

type proxifyResponse struct {
	Header map[string]string `json:"header" yaml:"header"`
	Body   string            `json:"body" yaml:"body"`
	Raw    string            `json:"raw" yaml:"raw"`
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
		finalData, err := ytt(tpl, dvs, j.opts.VarsFilePaths)
		if err != nil {
			return errors.Wrap(err, "could not apply ytt templating")
		}
		finalInput = bytes.NewReader(finalData)
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

		raw := request.Request.Raw
		if raw == "" {
			continue
		}

		rawRequest, err := types.ParseRawRequestWithURL(raw, request.URL)
		if err != nil {
			gologger.Warning().Msgf("multidoc-yaml: Could not parse raw request %s: %s", request.URL, err)
			continue
		}
		if resp := buildProxifyResponse(request.Response); resp != nil {
			rawRequest.Response = resp
		}
		resultsCb(rawRequest)
	}
	return nil
}

func buildProxifyResponse(resp *proxifyResponse) *types.HttpResponse {
	if resp == nil {
		return nil
	}
	raw := resp.Raw
	if raw == "" {
		return nil
	}
	if resp.Body != "" && (strings.HasSuffix(raw, "\r\n\r\n") || strings.HasSuffix(raw, "\n\n")) {
		raw += resp.Body
	}
	return &types.HttpResponse{
		Raw:  raw,
		Body: resp.Body,
	}
}
