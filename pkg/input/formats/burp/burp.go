package burp

import (
	"io"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	burpxml "github.com/projectdiscovery/utils/parsers/burp/xml"
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
	items, err := burpxml.ParseXML(input, burpxml.XMLParseOptions{DecodeBase64: true})
	if err != nil {
		return errors.Wrap(err, "could not decode burp xml schema")
	}

	for _, item := range items.Items {
		// Prefer decoded Body from burpxml; fall back to Raw. Do not TrimSpace the
		// payload — trailing blank lines mark end-of-headers for HTTP parsers.
		reqRaw := item.Request.Body
		if strings.TrimSpace(reqRaw) == "" {
			reqRaw = item.Request.Raw
		}
		if strings.TrimSpace(reqRaw) == "" {
			continue
		}
		rawRequest, err := types.ParseRawRequestWithURL(reqRaw, item.URL)
		if err != nil {
			return errors.Wrap(err, "could not parse raw request")
		}

		respRaw := item.Response.Body
		if strings.TrimSpace(respRaw) == "" {
			respRaw = item.Response.Raw
		}
		if strings.TrimSpace(respRaw) != "" {
			rawRequest.Response = &types.HttpResponse{Raw: respRaw}
		}

		resultsCb(rawRequest)
	}
	return nil
}
