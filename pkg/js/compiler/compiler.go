// Package compiler provides a compiler for the goja runtime.
package compiler

import (
	"context"
	"fmt"
	"time"

	"github.com/dop251/goja"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	contextutil "github.com/projectdiscovery/utils/context"
	stringsutil "github.com/projectdiscovery/utils/strings"
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
	// Callback can be used to register new runtime helper functions
	// ex: export etc
	Callback func(runtime *goja.Runtime) error

	// Cleanup is extra cleanup function to be called after execution
	Cleanup func(runtime *goja.Runtime)

	/// Timeout for this script execution
	Timeout int
	// Source is original source of the script
	Source *string

	Context context.Context

	// Manually exported objects
	exports map[string]interface{}
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
	p, err := WrapScriptNCompile(code, false)
	if err != nil {
		return nil, err
	}
	return c.ExecuteWithOptions(p, args, &ExecuteOptions{Context: context.Background()})
}

// ExecuteWithOptions executes a script with the provided options.
func (c *Compiler) ExecuteWithOptions(program *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (ExecuteResult, error) {
	if opts == nil {
		opts = &ExecuteOptions{Context: context.Background()}
	}
	if args == nil {
		args = NewExecuteArgs()
	}
	// handle nil maps
	if args.TemplateCtx == nil {
		args.TemplateCtx = make(map[string]interface{})
	}
	if args.Args == nil {
		args.Args = make(map[string]interface{})
	}
	// merge all args into templatectx
	args.TemplateCtx = generators.MergeMaps(args.TemplateCtx, args.Args)

	if opts.Timeout <= 0 || opts.Timeout > 180 {
		// some js scripts can take longer time so allow configuring timeout
		// from template but keep it within sane limits (180s)
		opts.Timeout = JsProtocolTimeout
	}

	// execute with context and timeout
	ctx, cancel := context.WithTimeout(opts.Context, time.Duration(opts.Timeout)*time.Second)
	defer cancel()
	// execute the script
	results, err := contextutil.ExecFuncWithTwoReturns(ctx, func() (val goja.Value, err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("panic: %v", r)
			}
		}()
		return ExecuteProgram(program, args, opts)
	})
	if err != nil {
		return nil, err
	}
	var res ExecuteResult
	if opts.exports != nil {
		res = ExecuteResult(opts.exports)
		opts.exports = nil
	} else {
		res = NewExecuteResult()
	}
	res["response"] = results.Export()
	res["success"] = results.ToBoolean()
	return res, nil
}

// Wraps a script in a function and compiles it.
func WrapScriptNCompile(script string, strict bool) (*goja.Program, error) {
	if !stringsutil.ContainsAny(script, exportAsToken, exportToken) {
		// this will not be run in a pooled runtime
		return goja.Compile("", script, strict)
	}
	val := fmt.Sprintf(`
		(function() {
			%s
		})()
	`, script)
	return goja.Compile("", val, strict)
}
