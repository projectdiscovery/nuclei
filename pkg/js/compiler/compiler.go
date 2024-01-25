// Package compiler provides a compiler for the goja runtime.
package compiler

import (
	"context"
	"time"

	"github.com/dop251/goja"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	contextutil "github.com/projectdiscovery/utils/context"
)

// Compiler provides a runtime to execute goja runtime
// based javascript scripts efficiently while also
// providing them access to custom modules defined in libs/.
type Compiler struct{}

// New creates a new compiler for the goja runtime.
func New() *Compiler {
	return &Compiler{}
}

// ExecuteOptions provides options for executing a script.
type ExecuteOptions struct {
	// Pool specifies whether to use a pool of goja runtimes
	// Can be used to speedup execution but requires
	// the script to not make any global changes.
	Pool bool

	// CaptureOutput specifies whether to capture the output
	// of the script execution.
	CaptureOutput bool

	// CaptureVariables specifies the variables to capture
	// from the script execution.
	CaptureVariables []string

	// Callback can be used to register new runtime helper functions
	// ex: export etc
	Callback func(runtime *goja.Runtime) error

	// Cleanup is extra cleanup function to be called after execution
	Cleanup func(runtime *goja.Runtime)

	/// Timeout for this script execution
	Timeout int
}

// ExecuteArgs is the arguments to pass to the script.
type ExecuteArgs struct {
	Args        map[string]interface{} //these are protocol variables
	TemplateCtx map[string]interface{} // templateCtx contains template scoped variables
}

// NewExecuteArgs returns a new execute arguments.
func NewExecuteArgs() *ExecuteArgs {
	return &ExecuteArgs{
		Args:        make(map[string]interface{}),
		TemplateCtx: make(map[string]interface{}),
	}
}

// ExecuteResult is the result of executing a script.
type ExecuteResult map[string]interface{}

func NewExecuteResult() ExecuteResult {
	return make(map[string]interface{})
}

// GetSuccess returns whether the script was successful or not.
func (e ExecuteResult) GetSuccess() bool {
	val, ok := e["success"].(bool)
	if !ok {
		return false
	}
	return val
}

// Execute executes a script with the default options.
func (c *Compiler) Execute(code string, args *ExecuteArgs) (ExecuteResult, error) {
	p, err := goja.Compile("", code, false)
	if err != nil {
		return nil, err
	}
	return c.ExecuteWithOptions(p, args, &ExecuteOptions{})
}

// ExecuteWithOptions executes a script with the provided options.
func (c *Compiler) ExecuteWithOptions(program *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (ExecuteResult, error) {
	if opts == nil {
		opts = &ExecuteOptions{}
	}
	if args == nil {
		args = NewExecuteArgs()
	}
	if args.TemplateCtx == nil {
		args.TemplateCtx = make(map[string]interface{})
	}
	// merge all args into templatectx
	args.TemplateCtx = generators.MergeMaps(args.TemplateCtx, args.Args)

	if opts.Timeout <= 0 || opts.Timeout > 180 {
		// some js scripts can take longer time so allow configuring timeout
		// from template but keep it within sane limits (180s)
		opts.Timeout = JsProtocolTimeout
	}

	// execute with context and timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Second)
	defer cancel()
	// execute the script
	results, err := contextutil.ExecFuncWithTwoReturns(ctx, func() (goja.Value, error) {
		return executeProgram(program, args, opts)
	})
	if err != nil {
		return nil, err
	}
	captured := results.Export()

	// if opts.CaptureOutput {
	// 	return convertOutputToResult(captured)
	// }
	// if len(opts.CaptureVariables) > 0 {
	// 	return c.captureVariables(runtime, opts.CaptureVariables)
	// }
	// success is true by default . since js throws errors on failure
	// hence output result is always success
	return ExecuteResult{"response": captured, "success": results.ToBoolean()}, nil
}

// // captureVariables captures the variables from the runtime.
// func (c *Compiler) captureVariables(runtime *goja.Runtime, variables []string) (ExecuteResult, error) {
// 	results := make(ExecuteResult, len(variables))
// 	for _, variable := range variables {
// 		value := runtime.Get(variable)
// 		if value == nil {
// 			continue
// 		}
// 		results[variable] = value.Export()
// 	}
// 	return results, nil
// }

// func convertOutputToResult(output interface{}) (ExecuteResult, error) {
// 	marshalled, err := jsoniter.Marshal(output)
// 	if err != nil {
// 		return nil, errors.Wrap(err, "could not marshal output")
// 	}

// 	var outputMap map[string]interface{}
// 	if err := jsoniter.Unmarshal(marshalled, &outputMap); err != nil {
// 		var v interface{}
// 		if unmarshalErr := jsoniter.Unmarshal(marshalled, &v); unmarshalErr != nil {
// 			return nil, unmarshalErr
// 		}
// 		outputMap = map[string]interface{}{"output": v}
// 		return outputMap, nil
// 	}
// 	return outputMap, nil
// }
