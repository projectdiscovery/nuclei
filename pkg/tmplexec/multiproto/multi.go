package multiproto

import (
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	mapsutil "github.com/projectdiscovery/utils/maps"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

// Mutliprotocol is a template executer engine that executes multiple protocols
// with logic in between
type MultiProtocol struct {
	requests     []protocols.Request
	options      *protocols.ExecutorOptions
	results      *atomic.Bool
	readOnlyArgs map[string]interface{} // readOnlyArgs are readonly args that are available after compilation
}

// NewMultiProtocol creates a new multiprotocol template engine from a list of requests
func NewMultiProtocol(requests []protocols.Request, options *protocols.ExecutorOptions, results *atomic.Bool) *MultiProtocol {
	if results == nil {
		results = &atomic.Bool{}
	}
	return &MultiProtocol{requests: requests, options: options, results: results}
}

// Compile engine specific compilation
func (m *MultiProtocol) Compile() error {
	// load all variables and evaluate with existing data
	variableMap := m.options.Variables.GetAll()
	// cli options
	optionVars := generators.BuildPayloadFromOptions(m.options.Options)
	// constants
	constants := m.options.Constants
	allVars := generators.MergeMaps(variableMap, constants, optionVars)
	allVars = m.options.Variables.Evaluate(allVars)
	m.readOnlyArgs = allVars
	// no need to load files since they are done at template level
	return nil
}

// ExecuteWithResults executes the template and returns results
func (m *MultiProtocol) ExecuteWithResults(ctx *scan.ScanContext) error {
	select {
	case <-ctx.Context().Done():
		return ctx.Context().Err()
	default:
	}

	// put all readonly args into template context
	m.options.GetTemplateCtx(ctx.Input.MetaInput).Merge(m.readOnlyArgs)

	// add all input args to template context
	ctx.Input.ForEach(func(key string, value interface{}) {
		m.options.GetTemplateCtx(ctx.Input.MetaInput).Set(key, value)
	})

	previous := mapsutil.NewSyncLockMap[string, any]()

	// template context: contains values extracted using `internal` extractor from previous protocols
	// these values are extracted from each protocol in queue and are passed to next protocol in queue
	// instead of adding seperator field to handle such cases these values are appended to `dynamicValues` (which are meant to be used in workflows)
	// this makes it possible to use multi protocol templates in workflows
	// Note: internal extractor values take precedence over dynamicValues from workflows (i.e other templates in workflow)

	// execute all protocols in the queue
	for _, req := range m.requests {
		select {
		case <-ctx.Context().Done():
			return ctx.Context().Err()
		default:
		}
		inputItem := ctx.Input.Clone()
		if m.options.InputHelper != nil && ctx.Input.MetaInput.Input != "" {
			if inputItem.MetaInput.Input = m.options.InputHelper.Transform(inputItem.MetaInput.Input, req.Type()); inputItem.MetaInput.Input == "" {
				return nil
			}
		}
		// FIXME: this hack of using hash to get templateCtx has known issues scan context based approach should be adopted ASAP
		values := m.options.GetTemplateCtx(inputItem.MetaInput).GetAll()
		err := req.ExecuteWithResults(inputItem, output.InternalEvent(values), output.InternalEvent(previous.GetAll()), func(event *output.InternalWrappedEvent) {
			if event == nil {
				return
			}

			ID := req.GetID()
			if ID != "" {
				builder := &strings.Builder{}
				for k, v := range event.InternalEvent {
					builder.WriteString(ID)
					builder.WriteString("_")
					builder.WriteString(k)
					_ = previous.Set(builder.String(), v)
					builder.Reset()
				}
			}

			// log event and generate result for the event
			ctx.LogEvent(event)
			// export dynamic values from operators (i.e internal:true)
			if event.OperatorsResult != nil && len(event.OperatorsResult.DynamicValues) > 0 {
				for k, v := range event.OperatorsResult.DynamicValues {
					// TBD: iterate-all is only supported in `http` protocol
					// we either need to add support for iterate-all in other protocols or implement a different logic (specific to template context)
					// currently if dynamic value array only contains one value we replace it with the value
					if len(v) == 1 {
						m.options.GetTemplateCtx(ctx.Input.MetaInput).Set(k, v[0])
					} else {
						// Note: if extracted value contains multiple values then they can be accessed by indexing
						// ex: if values are dynamic = []string{"a","b","c"} then they are available as
						// dynamic = "a" , dynamic1 = "b" , dynamic2 = "c"
						// we intentionally omit first index for unknown situations (where no of extracted values are not known)
						for i, val := range v {
							if i == 0 {
								m.options.GetTemplateCtx(ctx.Input.MetaInput).Set(k, val)
							} else {
								m.options.GetTemplateCtx(ctx.Input.MetaInput).Set(k+strconv.Itoa(i), val)
							}
						}
					}
				}
			}

			// evaluate all variables after execution of each protocol
			variableMap := m.options.Variables.Evaluate(m.options.GetTemplateCtx(ctx.Input.MetaInput).GetAll())
			m.options.GetTemplateCtx(ctx.Input.MetaInput).Merge(variableMap) // merge all variables into template context
		})
		// in case of fatal error skip execution of next protocols
		if err != nil {
			// always log errors
			ctx.LogError(err)
			// for some classes of protocols (i.e ssl) errors like tls handshake are a legitimate behavior so we don't stop execution
			// connection failures are already tracked by the internal host error cache
			// we use strings comparison as the error is not formalized into instance within the standard library
			// within a flow instead we consider ssl errors as fatal, since a specific logic was requested
			if req.Type() == types.SSLProtocol && stringsutil.ContainsAnyI(err.Error(), "protocol version not supported", "could not do tls handshake") {
				continue
			}
		}
	}
	return nil
}

// Name of the template engine
func (m *MultiProtocol) Name() string {
	return "multiproto"
}
