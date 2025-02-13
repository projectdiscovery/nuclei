package burp

import (
	"encoding/base64"
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/utils/conversion"
	"github.com/seh-msft/burpxml"
)

// BurpFormat is a Burp XML File parser
type BurpFormat struct {
	opts formats.InputFormatOptions
}

// New creates a new Burp XML File parser
func New() *BurpFormat {
	return &BurpFormat{}
}

var _ formats.Format = &BurpFormat{}

// Name returns the name of the format
func (j *BurpFormat) Name() string {
	return "burp"
}

func (j *BurpFormat) SetOptions(options formats.InputFormatOptions) {
	j.opts = options
}

// Parse parses the input and calls the provided callback
// function for each RawRequest it discovers.
func (j *BurpFormat) Parse(input io.Reader, resultsCb formats.ParseReqRespCallback, filePath string) error {
	items, err := burpxml.Parse(input, true)
	if err != nil {
		return errors.Wrap(err, "could not decode burp xml schema")
	}

	// Print the parsed data for verification
	for _, item := range items.Items {
		item := item
		binx, err := base64.StdEncoding.DecodeString(item.Request.Raw)
		if err != nil {
			return errors.Wrap(err, "could not decode base64")
		}
		if strings.TrimSpace(conversion.String(binx)) == "" {
			continue
		}
		rawRequest, err := types.ParseRawRequestWithURL(conversion.String(binx), item.Url)
		if err != nil {
			return errors.Wrap(err, "could not parse raw request")
		}
		resultsCb(rawRequest) // TODO: Handle false and true from callback
	}
	return nil
}
