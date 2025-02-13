package http

import (
	"bytes"
	"io"
	"os"
	"strings"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/burp"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/openapi"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/swagger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/yaml"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
)

// HttpMultiFormatOptions contains options for the http input provider
type HttpMultiFormatOptions struct {
	// Options for the http input provider
	Options formats.InputFormatOptions
	// InputFile is the file containing the input
	InputFile string
	// InputMode is the mode of input
	InputMode string

	// optional input reader
	InputContents string
}

// HttpInputProvider implements an input provider for nuclei that loads
// inputs from multiple formats like burp, openapi, postman,proxify, etc.
type HttpInputProvider struct {
	format    formats.Format
	inputData []byte
	inputFile string
	count     int64
}

// NewHttpInputProvider creates a new input provider for nuclei from a file
// or an input string
//
// The first preference is given to input file if provided
// otherwise it will use the input string
func NewHttpInputProvider(opts *HttpMultiFormatOptions) (*HttpInputProvider, error) {
	var format formats.Format
	for _, provider := range providersList {
		if provider.Name() == opts.InputMode {
			format = provider
		}
	}
	if format == nil {
		return nil, errors.Errorf("invalid input mode %s", opts.InputMode)
	}
	format.SetOptions(opts.Options)
	// Do a first pass over the input to identify any errors
	// and get the count of the input file as well
	count := int64(0)
	var inputFile *os.File
	var inputReader io.Reader
	if opts.InputFile != "" {
		file, err := os.Open(opts.InputFile)
		if err != nil {
			return nil, errors.Wrap(err, "could not open input file")
		}
		inputFile = file
		inputReader = file
	} else {
		inputReader = strings.NewReader(opts.InputContents)
	}
	defer func() {
		if inputFile != nil {
			inputFile.Close()
		}
	}()

	data, err := io.ReadAll(inputReader)
	if err != nil {
		return nil, errors.Wrap(err, "could not read input file")
	}
	if len(data) == 0 {
		return nil, errors.New("input file is empty")
	}

	parseErr := format.Parse(bytes.NewReader(data), func(request *types.RequestResponse) bool {
		count++
		return false
	}, opts.InputFile)
	if parseErr != nil {
		return nil, errors.Wrap(parseErr, "could not parse input file")
	}
	return &HttpInputProvider{format: format, inputData: data, inputFile: opts.InputFile, count: count}, nil
}

// Count returns the number of items for input provider
func (i *HttpInputProvider) Count() int64 {
	return i.count
}

// Iterate over all inputs in order
func (i *HttpInputProvider) Iterate(callback func(value *contextargs.MetaInput) bool) {
	err := i.format.Parse(bytes.NewReader(i.inputData), func(request *types.RequestResponse) bool {
		metaInput := contextargs.NewMetaInput()
		metaInput.ReqResp = request
		metaInput.Input = request.URL.String()
		return callback(metaInput)
	}, i.inputFile)
	if err != nil {
		gologger.Warning().Msgf("Could not parse input file while iterating: %s\n", err)
	}
}

// Set adds item to input provider
// No-op for this provider
func (i *HttpInputProvider) Set(value string) {}

// SetWithProbe adds item to input provider with http probing
// No-op for this provider
func (i *HttpInputProvider) SetWithProbe(value string, probe types.InputLivenessProbe) error {
	return nil
}

// SetWithExclusions adds item to input provider if it doesn't match any of the exclusions
// No-op for this provider
func (i *HttpInputProvider) SetWithExclusions(value string) error {
	return nil
}

// InputType returns the type of input provider
func (i *HttpInputProvider) InputType() string {
	return "MultiFormatInputProvider"
}

// Close closes the input provider and cleans up any resources
// No-op for this provider
func (i *HttpInputProvider) Close() {}

// Supported Providers
var providersList = []formats.Format{
	burp.New(),
	json.New(),
	yaml.New(),
	openapi.New(),
	swagger.New(),
}

// SupportedFormats returns the list of supported formats in comma-separated
// manner
func SupportedFormats() string {
	var formats []string
	for _, provider := range providersList {
		formats = append(formats, provider.Name())
	}
	return strings.Join(formats, ", ")
}
