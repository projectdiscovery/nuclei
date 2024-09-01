package provider

import (
	"errors"
	"fmt"
	"strings"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/formats"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider/http"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider/list"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	configTypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	ErrNotImplemented = errorutil.NewWithFmt("provider %s does not implement %s")
	ErrInactiveInput  = fmt.Errorf("input is inactive")
)

const (
	MultiFormatInputProvider = "MultiFormatInputProvider"
	ListInputProvider        = "ListInputProvider"
	SimpleListInputProvider  = "SimpleInputProvider"
)

// IsErrNotImplemented checks if an error is a not implemented error
func IsErrNotImplemented(err error) bool {
	if err == nil {
		return false
	}
	if stringsutil.ContainsAll(err.Error(), "provider", "does not implement") {
		return true
	}
	return false
}

// Validate all Implementations
var (
	// SimpleInputProvider is more like a No-Op and returns given list of urls as input
	_ InputProvider = &SimpleInputProvider{}
	// HttpInputProvider provides support for formats that contain complete request/response
	// like burp, openapi, postman,proxify, etc.
	_ InputProvider = &http.HttpInputProvider{}
	// ListInputProvider provides support for simple list of urls or files etc
	_ InputProvider = &list.ListInputProvider{}
)

// InputProvider is unified input provider interface that provides
// processed inputs to nuclei by parsing and providing different
// formats such as list,openapi,postman,proxify,burp etc.
type InputProvider interface {
	// Count returns total targets for input provider
	Count() int64
	// Iterate over all inputs in order
	Iterate(callback func(value *contextargs.MetaInput) bool)
	// Set adds item to input provider
	Set(value string)
	// SetWithProbe adds item to input provider with http probing
	SetWithProbe(value string, probe types.InputLivenessProbe) error
	// SetWithExclusions adds item to input provider if it doesn't match any of the exclusions
	SetWithExclusions(value string) error
	// InputType returns the type of input provider
	InputType() string
	// Close the input provider and cleanup any resources
	Close()
}

// InputOptions contains options for input provider
type InputOptions struct {
	// Options for global config
	Options *configTypes.Options
	// NotFoundCallback is the callback to call when input is not found
	// only supported in list input provider
	NotFoundCallback func(template string) bool
}

// NewInputProvider creates a new input provider based on the options
// and returns it
func NewInputProvider(opts InputOptions) (InputProvider, error) {
	// optionally load generated vars values if available
	val, err := formats.ReadOpenAPIVarDumpFile()
	if err != nil && !errors.Is(err, formats.ErrNoVarsDumpFile) {
		// log error and continue
		gologger.Error().Msgf("Could not read vars dump file: %s\n", err)
	}
	extraVars := make(map[string]interface{})
	if val != nil {
		for _, v := range val.Var {
			v = strings.TrimSpace(v)
			// split into key value
			parts := strings.SplitN(v, "=", 2)
			if len(parts) == 2 {
				extraVars[parts[0]] = parts[1]
			}
		}
	}

	// check if input provider is supported
	if strings.EqualFold(opts.Options.InputFileMode, "list") {
		// create a new list input provider
		return list.New(&list.Options{
			Options:          opts.Options,
			NotFoundCallback: opts.NotFoundCallback,
		})
	} else {
		// use HttpInputProvider
		return http.NewHttpInputProvider(&http.HttpMultiFormatOptions{
			InputFile: opts.Options.TargetsFilePath,
			InputMode: opts.Options.InputFileMode,
			Options: formats.InputFormatOptions{
				Variables:            generators.MergeMaps(extraVars, opts.Options.Vars.AsMap()),
				SkipFormatValidation: opts.Options.SkipFormatValidation,
				RequiredOnly:         opts.Options.FormatUseRequiredOnly,
			},
		})
	}
}

// SupportedInputFormats returns all supported input formats of nuclei
func SupportedInputFormats() string {
	return "list, " + http.SupportedFormats()
}
