package burp

import (
	"os"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/seh-msft/burpxml"
)

// BurpFormat is a Burp XML File parser
type BurpFormat struct{}

// New creates a new Burp XML File parser
func New() *BurpFormat {
	return &BurpFormat{}
}

var _ formats.Format = &BurpFormat{}

// Name returns the name of the format
func (j *BurpFormat) Name() string {
	return "burp"
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *BurpFormat) Parse(input string, resultsCb formats.RawRequestCallback) error {
	file, err := os.Open(input)
	if err != nil {
		return errors.Wrap(err, "could not open data file")
	}
	defer file.Close()

	items, err := burpxml.Parse(file, true)
	if err != nil {
		return errors.Wrap(err, "could not decode burp xml schema")
	}

	// Print the parsed data for verification
	for _, item := range items.Items {
		item := item

		rawRequest, err := formats.ParseRawRequest(item.Request.Body, "", item.Url)
		if err != nil {
			continue
		}
		resultsCb(rawRequest) // TODO: Handle false and true from callback
	}
	return nil
}
