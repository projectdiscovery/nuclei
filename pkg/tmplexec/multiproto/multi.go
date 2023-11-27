package multiproto

import (
	"strconv"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
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
	// put all readonly args into template context
	m.options.GetTemplateCtx(ctx.Input.MetaInput).Merge(m.readOnlyArgs)
	var finalProtoEvent *output.InternalWrappedEvent
	// callback to process results from all protocols
	multiProtoCallback := func(event *output.InternalWrappedEvent) {
		if event != nil {
			finalProtoEvent = event
		}
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
	}

	// template context: contains values extracted using `internal` extractor from previous protocols
	// these values are extracted from each protocol in queue and are passed to next protocol in queue
	// instead of adding seperator field to handle such cases these values are appended to `dynamicValues` (which are meant to be used in workflows)
	// this makes it possible to use multi protocol templates in workflows
	// Note: internal extractor values take precedence over dynamicValues from workflows (i.e other templates in workflow)

	// execute all protocols in the queue
	for _, req := range m.requests {
		values := m.options.GetTemplateCtx(ctx.Input.MetaInput).GetAll()
		err := req.ExecuteWithResults(ctx.Input, output.InternalEvent(values), nil, multiProtoCallback)
		// if error skip execution of next protocols
		if err != nil {
			ctx.LogError(err)
			return err
		}
	}
	// Review: how to handle events of multiple protocols in a single template
	// currently the outer callback is only executed once (for the last protocol in queue)
	// due to workflow logic at https://github.com/projectdiscovery/nuclei/blob/main/pkg/protocols/common/executer/executem.go#L150
	// this causes addition of duplicated / unncessary variables with prefix template_id_all_variables
	ctx.LogEvent(finalProtoEvent)

	return nil
}

// Name of the template engine
func (m *MultiProtocol) Name() string {
	return "multiproto"
}
