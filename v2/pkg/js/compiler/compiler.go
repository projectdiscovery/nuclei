// Package compiler provides a compiler for the goja runtime.
package compiler

import (
	"runtime/debug"

	"github.com/dop251/goja"
	"github.com/dop251/goja_nodejs/console"
	"github.com/dop251/goja_nodejs/require"
	jsoniter "github.com/json-iterator/go"

	"github.com/projectdiscovery/gologger"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libkerberos"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/liblayers"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libldap"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libmssql"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libmysql"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libnet"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/liboracle"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libpop3"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libpostgres"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/librdp"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libredis"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/librsync"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libsmb"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libsmtp"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libssh"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libtelnet"
	_ "github.com/projectdiscovery/nuclei/v2/pkg/js/generated/go/libvnc"
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
	var customPrinter console.Printer = console.PrinterFunc(func(s string) {
		gologger.Debug().Label("console").Msgf("%s", s)
	})
	require.RegisterNativeModule(console.ModuleName, console.RequireWithPrinter(customPrinter))

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
}

// ExecuteArgs is the arguments to pass to the script.
type ExecuteArgs map[string]interface{}

// ExecuteResult is the result of executing a script.
type ExecuteResult map[string]interface{}

// GetSuccess returns whether the script was successful or not.
func (e ExecuteResult) GetSuccess() bool {
	val, ok := e["success"].(bool)
	if !ok {
		return false
	}
	return val
}

// Execute executes a script with the default options.
func (c *Compiler) Execute(code string, args ExecuteArgs) (ExecuteResult, error) {
	return c.ExecuteWithOptions(code, args, &ExecuteOptions{})
}

// VM returns a new goja runtime for the compiler.
func (c *Compiler) VM() *goja.Runtime {
	runtime := c.newRuntime(false)
	c.registerHelpersForVM(runtime)
	return runtime
}

// ExecuteWithOptions executes a script with the provided options.
func (c *Compiler) ExecuteWithOptions(code string, args ExecuteArgs, opts *ExecuteOptions) (ExecuteResult, error) {
	defer func() {
		if err := recover(); err != nil {
			gologger.Warning().Msgf("Recovered panic %s %v: %v", code, args, err)
			debug.PrintStack()
			return
		}
	}()

	runtime := c.newRuntime(opts.Pool)
	c.registerHelpersForVM(runtime)

	for k, v := range args {
		runtime.Set(k, v)
	}
	results, err := runtime.RunString(code)
	if err != nil {
		return nil, err
	}
	captured := results.Export()

	// If we need to capture output, we need to do it here.
	// FIXME: This doesn't work with kval and returns blank response
	// fix this.
	if opts.CaptureOutput {
		return convertOutputToResult(captured)
	}
	if len(opts.CaptureVariables) > 0 {
		return c.captureVariables(runtime, opts.CaptureVariables)
	}
	var resultsBool bool
	if val, ok := captured.(bool); ok {
		resultsBool = val
	}
	return ExecuteResult{"success": resultsBool}, nil
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
	marshalled, _ := jsoniter.Marshal(output)
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
	return goja.New()
}
