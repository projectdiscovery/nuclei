package flow

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
	fileutil "github.com/projectdiscovery/utils/file"
	mapsutil "github.com/projectdiscovery/utils/maps"
	"go.uber.org/multierr"
)

var (
	// ErrInvalidRequestID is a request id error
	ErrInvalidRequestID = errorutil.NewWithFmt("[%s] invalid request id '%s' provided")
)

// ProtoOptions are options that can be passed to flow protocol callback
// ex: dns(protoOptions) <- protoOptions are optional and can be anything
type ProtoOptions struct {
	protoName string
	reqIDS    []string
}

// FlowExecutor is a flow executor for executing a flow
type FlowExecutor struct {
	input   *contextargs.Context
	options *protocols.ExecutorOptions

	// javascript runtime reference and compiled program
	jsVM      *goja.Runtime
	program   *goja.Program                // compiled js program
	lastEvent *output.InternalWrappedEvent // contains last event that was emitted

	// protocol requests and their callback functions
	allProtocols   map[string][]protocols.Request
	protoFunctions map[string]func(call goja.FunctionCall) goja.Value // reqFunctions contains functions that allow executing requests/protocols from js

	// logic related variables
	results *atomic.Bool
	allErrs mapsutil.SyncLockMap[string, error]
}

// NewFlowExecutor creates a new flow executor from a list of requests
func NewFlowExecutor(requests []protocols.Request, input *contextargs.Context, options *protocols.ExecutorOptions, results *atomic.Bool) *FlowExecutor {
	allprotos := make(map[string][]protocols.Request)
	for _, req := range requests {
		switch req.Type() {
		case templateTypes.DNSProtocol:
			allprotos[templateTypes.DNSProtocol.String()] = append(allprotos[templateTypes.DNSProtocol.String()], req)
		case templateTypes.HTTPProtocol:
			allprotos[templateTypes.HTTPProtocol.String()] = append(allprotos[templateTypes.HTTPProtocol.String()], req)
		case templateTypes.NetworkProtocol:
			allprotos[templateTypes.NetworkProtocol.String()] = append(allprotos[templateTypes.NetworkProtocol.String()], req)
		case templateTypes.FileProtocol:
			allprotos[templateTypes.FileProtocol.String()] = append(allprotos[templateTypes.FileProtocol.String()], req)
		case templateTypes.HeadlessProtocol:
			allprotos[templateTypes.HeadlessProtocol.String()] = append(allprotos[templateTypes.HeadlessProtocol.String()], req)
		case templateTypes.SSLProtocol:
			allprotos[templateTypes.SSLProtocol.String()] = append(allprotos[templateTypes.SSLProtocol.String()], req)
		case templateTypes.WebsocketProtocol:
			allprotos[templateTypes.WebsocketProtocol.String()] = append(allprotos[templateTypes.WebsocketProtocol.String()], req)
		case templateTypes.WHOISProtocol:
			allprotos[templateTypes.WHOISProtocol.String()] = append(allprotos[templateTypes.WHOISProtocol.String()], req)
		case templateTypes.CodeProtocol:
			allprotos[templateTypes.CodeProtocol.String()] = append(allprotos[templateTypes.CodeProtocol.String()], req)
		case templateTypes.JavascriptProtocol:
			allprotos[templateTypes.JavascriptProtocol.String()] = append(allprotos[templateTypes.JavascriptProtocol.String()], req)
		default:
			gologger.Error().Msgf("invalid request type %s", req.Type().String())
		}
	}
	f := &FlowExecutor{
		allProtocols: allprotos,
		options:      options,
		allErrs: mapsutil.SyncLockMap[string, error]{
			ReadOnly: atomic.Bool{},
			Map:      make(map[string]error),
		},
		protoFunctions: map[string]func(call goja.FunctionCall) goja.Value{},
		results:        results,
		jsVM:           protocolstate.NewJSRuntime(),
		input:          input,
	}
	return f
}

// Compile compiles js program and registers all functions
func (f *FlowExecutor) Compile() error {
	if f.results == nil {
		f.results = new(atomic.Bool)
	}
	// load all variables and evaluate with existing data
	variableMap := f.options.Variables.Evaluate(f.options.GetTemplateCtx(f.input.MetaInput).GetAll())
	// cli options
	optionVars := generators.BuildPayloadFromOptions(f.options.Options)
	// constants
	constants := f.options.Constants
	allVars := generators.MergeMaps(variableMap, constants, optionVars)
	// we support loading variables from files in variables , cli options and constants
	// try to load if files exist
	for k, v := range allVars {
		if str, ok := v.(string); ok && len(str) < 150 && fileutil.FileExists(str) {
			if value, err := f.ReadDataFromFile(str); err == nil {
				allVars[k] = value
			} else {
				gologger.Warning().Msgf("could not load file '%s' for variable '%s': %s", str, k, err)
			}
		}
	}
	f.options.GetTemplateCtx(f.input.MetaInput).Merge(allVars) // merge all variables into template context

	// ---- define callback functions/objects----
	f.protoFunctions = map[string]func(call goja.FunctionCall) goja.Value{}
	// iterate over all protocols and generate callback functions for each protocol
	for p, requests := range f.allProtocols {
		// for each protocol build a requestMap with reqID and protocol request
		reqMap := mapsutil.Map[string, protocols.Request]{}
		counter := 0
		proto := strings.ToLower(p) // donot use loop variables in callback functions directly
		for index := range requests {
			counter++ // start index from 1
			request := f.allProtocols[proto][index]
			if request.GetID() != "" {
				// if id is present use it
				reqMap[request.GetID()] = request
			}
			// fallback to using index as id
			// always allow index as id as a fallback
			reqMap[strconv.Itoa(counter)] = request
		}
		// ---define hook that allows protocol/request execution from js-----
		// --- this is the actual callback that is executed when function is invoked in js----
		f.protoFunctions[proto] = func(call goja.FunctionCall) goja.Value {
			opts := &ProtoOptions{
				protoName: proto,
			}
			for _, v := range call.Arguments {
				switch value := v.Export().(type) {
				default:
					opts.reqIDS = append(opts.reqIDS, types.ToString(value))
				}
			}
			return f.jsVM.ToValue(f.requestExecutor(reqMap, opts))
		}
	}
	return f.registerBuiltInFunctions()
}

// ExecuteWithResults executes the flow and returns results
func (f *FlowExecutor) ExecuteWithResults(ctx *scan.ScanContext) error {
	defer func() {
		if e := recover(); e != nil {
			gologger.Error().Label(f.options.TemplateID).Msgf("panic occurred while executing target %v with flow: %v", ctx.Input.MetaInput.Input, e)
			panic(e)
		}
	}()

	f.input = ctx.Input
	// -----Load all types of variables-----
	// add all input args to template context
	if f.input != nil && f.input.HasArgs() {
		f.input.ForEach(func(key string, value interface{}) {
			f.options.GetTemplateCtx(f.input.MetaInput).Set(key, value)
		})
	}
	if ctx.OnResult == nil {
		return fmt.Errorf("output callback cannot be nil")
	}
	// pass flow and execute the js vm and handle errors
	value, err := f.jsVM.RunProgram(f.program)
	if err != nil {
		ctx.LogError(err)
		return errorutil.NewWithErr(err).Msgf("failed to execute flow\n%v\n", f.options.Flow)
	}
	runtimeErr := f.GetRuntimeErrors()
	if runtimeErr != nil {
		ctx.LogError(runtimeErr)
		return errorutil.NewWithErr(runtimeErr).Msgf("got following errors while executing flow")
	}
	// this is where final result is generated/created
	ctx.LogEvent(f.lastEvent)
	if value.Export() != nil {
		f.results.Store(value.ToBoolean())
	} else {
		f.results.Store(true)
	}
	return nil
}

// GetRuntimeErrors returns all runtime errors (i.e errors from all protocol combined)
func (f *FlowExecutor) GetRuntimeErrors() error {
	errs := []error{}
	for proto, err := range f.allErrs.GetAll() {
		errs = append(errs, errorutil.NewWithErr(err).Msgf("failed to execute %v protocol", proto))
	}
	return multierr.Combine(errs...)
}

// ReadDataFromFile reads data from file respecting sandbox options
func (f *FlowExecutor) ReadDataFromFile(payload string) ([]string, error) {
	values := []string{}
	// load file respecting sandbox
	reader, err := f.options.Options.LoadHelperFile(payload, f.options.TemplatePath, f.options.Catalog)
	if err != nil {
		return values, err
	}
	defer reader.Close()
	bin, err := io.ReadAll(reader)
	if err != nil {
		return values, err
	}
	for _, line := range strings.Split(string(bin), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			values = append(values, line)
		}
	}
	return values, nil
}

// Name returns the type of engine
func (f *FlowExecutor) Name() string {
	return "flow"
}
