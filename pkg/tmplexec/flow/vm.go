package flow

import (
	"reflect"

	"github.com/dop251/goja"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/flow/builtin"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// GetJSRuntime returns a new JS runtime.
//
// A new runtime is created for each call to avoid state leakage between
// executions.
func GetJSRuntime(opts *types.Options) *goja.Runtime {
	runtime := protocolstate.NewJSRuntime()
	registerBuiltins(runtime)
	return runtime
}

// PutJSRuntime returns a JS runtime to pool
//
// Deprecated: This function is a no-op and does not do anything.
func PutJSRuntime(runtime *goja.Runtime) {
	// Do nothing.
}

func registerBuiltins(runtime *goja.Runtime) {
	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name:        "log",
		Description: "Logs a given object/message to stdout (only for debugging purposes)",
		Signatures: []string{
			"log(obj any) any",
		},
		FuncDecl: func(call goja.FunctionCall) goja.Value {
			arg := call.Argument(0).Export()
			switch value := arg.(type) {
			case string:
				gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), value)
			case map[string]interface{}:
				gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), vardump.DumpVariables(value))
			default:
				gologger.DefaultLogger.Print().Msgf("[%v] %v", aurora.BrightCyan("JS"), value)
			}
			return call.Argument(0) // return the same value
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name:        "iterate",
		Description: "Normalizes and Iterates over all arguments (can be a string,array,null etc) and returns an array of objects\nNote: If the object type is unknown(i.e could be a string or array) iterate should be used and it will always return an array of strings",
		Signatures: []string{
			"iterate(...any) []any",
		},
		FuncDecl: func(call goja.FunctionCall) goja.Value {
			allVars := []any{}
			for _, v := range call.Arguments {
				if v.Export() == nil {
					continue
				}
				if v.ExportType().Kind() == reflect.Slice {
					// convert []datatype to []interface{}
					// since it cannot be type asserted to []interface{} directly
					rfValue := reflect.ValueOf(v.Export())
					for i := 0; i < rfValue.Len(); i++ {
						allVars = append(allVars, rfValue.Index(i).Interface())
					}
				} else {
					allVars = append(allVars, v.Export())
				}
			}
			return runtime.ToValue(allVars)
		},
	})

	_ = gojs.RegisterFuncWithSignature(runtime, gojs.FuncOpts{
		Name:        "Dedupe",
		Description: "De-duplicates given values and returns a new array of unique values",
		Signatures: []string{
			"new Dedupe()",
		},
		FuncDecl: func(call goja.ConstructorCall) *goja.Object {
			d := builtin.NewDedupe(runtime)
			obj := call.This
			// register these methods
			_ = obj.Set("Add", d.Add)
			_ = obj.Set("Values", d.Values)
			return nil
		},
	})

}
