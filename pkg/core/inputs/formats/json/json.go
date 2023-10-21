package json

import (
	"encoding/json"
	"io"
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/core/inputs/formats"
)

// JSONFormat is a JSON format parser for nuclei
// input HTTP requests
type JSONFormat struct{}

// New creates a new JSON format parser
func New() *JSONFormat {
	return &JSONFormat{}
}

var _ formats.Format = &JSONFormat{}

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
func (j *JSONFormat) Name() string {
	return "jsonl"
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *JSONFormat) Parse(input string, resultsCb formats.RawRequestCallback) error {
	file, err := os.Open(input)
	if err != nil {
		return errors.Wrap(err, "could not open json file")
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	for {
		var request proxifyRequest
		err := decoder.Decode(&request)
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.Wrap(err, "could not decode json file")
		}

		rawRequest, err := formats.ParseRawRequest(request.Request.Raw, request.Request.Body, request.URL)
		if err != nil {
			gologger.Warning().Msgf("Could not parse raw request %s: %s\n", request.URL, err)
			continue
		}

		if !resultsCb(rawRequest) {
			break
		}
	}
	return nil
}
