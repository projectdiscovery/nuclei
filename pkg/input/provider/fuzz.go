package provider

// import (
// 	"strings"

// 	"github.com/pkg/errors"
// 	"github.com/projectdiscovery/gologger"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/burp"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/json"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/openapi"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/postman"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats/swagger"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
// )

// var providersList = []formats.Format{
// 	burp.New(),
// 	json.New(),
// 	openapi.New(),
// 	postman.New(),
// 	swagger.New(),
// }

// // Formats returns the list of supported formats in comma-separated
// // manner
// func Formats() string {
// 	var formats []string
// 	for _, provider := range providersList {
// 		formats = append(formats, provider.Name())
// 	}
// 	return strings.Join(formats, ", ")
// }

// // InputProvider is an interface implemented by format nuclei input provider
// type InputProvider struct {
// 	format    formats.Format
// 	inputFile string
// 	count     int64
// }

// // NewInputProvider creates a new input provider
// //
// // TODO: Currently the provider does not cache results. If we see this
// // parsing everytime being slow we can maybe switch, but this uses less memory
// // so it has been implemented this way.
// func NewInputProvider(inputFile, inputMode string) (*InputProvider, error) {
// 	var format formats.Format
// 	for _, provider := range providersList {
// 		if provider.Name() == inputMode {
// 			format = provider
// 		}
// 	}
// 	if format == nil {
// 		return nil, errors.Errorf("invalid input mode %s", inputMode)
// 	}

// 	// Do a first pass over the input to identify any errors
// 	// and get the count of the input file as well
// 	count := int64(0)
// 	parseErr := format.Parse(inputFile, func(request *types.RequestResponse) bool {
// 		count++
// 		return false
// 	})
// 	if parseErr != nil {
// 		return nil, errors.Wrap(parseErr, "could not parse input file")
// 	}
// 	return &InputProvider{format: format, inputFile: inputFile, count: count}, nil
// }

// // Count returns the number of items for input provider
// func (i *InputProvider) Count() int64 {
// 	return i.count
// }

// // Scan iterates the input and each found item is passed to the
// // callback consumer.
// func (i *InputProvider) Scan(callback func(value *contextargs.MetaInput) bool) {
// 	err := i.format.Parse(i.inputFile, func(request *types.RequestResponse) bool {
// 		return callback(&contextargs.MetaInput{
// 			ReqResp: request,
// 		})
// 	})
// 	if err != nil {
// 		gologger.Warning().Msgf("Could not parse input file: %s\n", err)
// 	}
// }

// // Set adds item to input provider
// func (i *InputProvider) Set(value string) {}
