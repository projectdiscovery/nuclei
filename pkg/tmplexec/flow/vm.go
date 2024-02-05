package flow

import (
	"reflect"
	"sync"

	"github.com/dop251/goja"
	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec/flow/builtin"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/remeh/sizedwaitgroup"
)

type jsWaitGroup struct {
	sync.Once
	sg sizedwaitgroup.SizedWaitGroup
}

var jsPool = &jsWaitGroup{}

// GetJSRuntime returns a new JS runtime from pool
func GetJSRuntime(opts *types.Options) *goja.Runtime {
	jsPool.Do(func() {
		if opts.JsConcurrency < 100 {
			opts.JsConcurrency = 100
		}
		jsPool.sg = sizedwaitgroup.New(opts.JsConcurrency)
	})
	jsPool.sg.Add()
	return gojapool.Get().(*goja.Runtime)
}

// PutJSRuntime returns a JS runtime to pool
func PutJSRuntime(runtime *goja.Runtime) {
	defer jsPool.sg.Done()
	gojapool.Put(runtime)
}

// js runtime pool using sync.Pool
var gojapool = &sync.Pool{
	New: func() interface{} {
		runtime := protocolstate.NewJSRuntime()
		registerBuiltins(runtime)
		return runtime
	},
}

func registerBuiltins(runtime *goja.Runtime) {
	_ = runtime.Set("log", func(call goja.FunctionCall) goja.Value {
		// TODO: verify string interpolation and handle multiple args
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
	})

	_ = runtime.Set("iterate", func(call goja.FunctionCall) goja.Value {
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
	})

	_ = runtime.Set("Dedupe", func(call goja.ConstructorCall) *goja.Object {
		d := builtin.NewDedupe(runtime)
		obj := call.This
		// register these methods
		_ = obj.Set("Add", d.Add)
		_ = obj.Set("Values", d.Values)
		return nil
	})
}
