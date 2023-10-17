// Package compiler provides a compiler for the goja runtime.
package compiler

import (
	"runtime/debug"

	"github.com/dop251/goja"
	"github.com/dop251/goja/parser"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
	jsoniter "github.com/json-iterator/go"
	"github.com/pkg/errors"

	"github.com/projectdiscovery/gologger"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libbytes"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libfs"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libikev2"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libkerberos"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libldap"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libmssql"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libmysql"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libnet"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/liboracle"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libpop3"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libpostgres"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/librdp"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libredis"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/librsync"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libsmb"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libsmtp"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libssh"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libstructs"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libtelnet"
	_ "github.com/projectdiscovery/nuclei/v3/pkg/js/generated/go/libvnc"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/global"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/libs/goconsole"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// Compiler provides a runtime to execute goja runtime
// based javascript scripts efficiently while also
// providing them access to custom modules defined in libs/.
type Compiler struct {
	registry *require.Registry
}

// New creates a new compiler for the goja runtime.
func New() *Compiler {
	registry := new(require.Registry) // this can be shared by multiple runtimes
	// autoregister console node module with default printer it uses gologger backend
	require.RegisterNativeModule(console.ModuleName, console.RequireWithPrinter(goconsole.NewGoConsolePrinter()))
	return &Compiler{registry: registry}
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
	return c.ExecuteWithOptions(code, args, &ExecuteOptions{})
}

// VM returns a new goja runtime for the compiler.
func (c *Compiler) VM() *goja.Runtime {
	runtime := c.newRuntime(false)
	runtime.SetParserOptions(parser.WithDisableSourceMaps)
	c.registerHelpersForVM(runtime)
	return runtime
}

// ExecuteWithOptions executes a script with the provided options.
func (c *Compiler) ExecuteWithOptions(code string, args *ExecuteArgs, opts *ExecuteOptions) (ExecuteResult, error) {
	defer func() {
		if err := recover(); err != nil {
			gologger.Error().Msgf("Recovered panic %s %v: %v", code, args, err)
			gologger.Verbose().Msgf("%s", debug.Stack())
			return
		}
	}()
	if opts == nil {
		opts = &ExecuteOptions{}
	}
	runtime := c.newRuntime(opts.Pool)
	c.registerHelpersForVM(runtime)

	// register runtime functions if any
	if opts.Callback != nil {
		if err := opts.Callback(runtime); err != nil {
			return nil, err
		}
	}

	if args == nil {
		args = NewExecuteArgs()
	}
	for k, v := range args.Args {
		_ = runtime.Set(k, v)
	}
	if args.TemplateCtx == nil {
		args.TemplateCtx = make(map[string]interface{})
	}
	// merge all args into templatectx
	args.TemplateCtx = generators.MergeMaps(args.TemplateCtx, args.Args)
	_ = runtime.Set("template", args.TemplateCtx)

	results, err := runtime.RunString(code)
	if err != nil {
		return nil, err
	}
	captured := results.Export()

	if opts.CaptureOutput {
		return convertOutputToResult(captured)
	}
	if len(opts.CaptureVariables) > 0 {
		return c.captureVariables(runtime, opts.CaptureVariables)
	}
	// success is true by default . since js throws errors on failure
	// hence output result is always success
	return ExecuteResult{"response": captured, "success": results.ToBoolean()}, nil
}

// captureVariables captures the variables from the runtime.
func (c *Compiler) captureVariables(runtime *goja.Runtime, variables []string) (ExecuteResult, error) {
	results := make(ExecuteResult, len(variables))
	for _, variable := range variables {
		value := runtime.Get(variable)
		if value == nil {
			continue
		}
		results[variable] = value.Export()
	}
	return results, nil
}

func convertOutputToResult(output interface{}) (ExecuteResult, error) {
	marshalled, err := jsoniter.Marshal(output)
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal output")
	}

	var outputMap map[string]interface{}
	if err := jsoniter.Unmarshal(marshalled, &outputMap); err != nil {
		var v interface{}
		if unmarshalErr := jsoniter.Unmarshal(marshalled, &v); unmarshalErr != nil {
			return nil, unmarshalErr
		}
		outputMap = map[string]interface{}{"output": v}
		return outputMap, nil
	}
	return outputMap, nil
}

// newRuntime creates a new goja runtime
// TODO: Add support for runtime reuse for helper functions
func (c *Compiler) newRuntime(reuse bool) *goja.Runtime {
	return protocolstate.NewJSRuntime()
}

// registerHelpersForVM registers all the helper functions for the goja runtime.
func (c *Compiler) registerHelpersForVM(runtime *goja.Runtime) {
	_ = c.registry.Enable(runtime)
	// by default import below modules every time
	_ = runtime.Set("console", require.Require(runtime, console.ModuleName))

	// Register embedded scripts
	if err := global.RegisterNativeScripts(runtime); err != nil {
		gologger.Error().Msgf("Could not register scripts: %s\n", err)
	}
}
