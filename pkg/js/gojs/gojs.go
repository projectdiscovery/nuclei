package gojs

import (
	"context"
	"reflect"
	"sync"

	"github.com/Mzack9999/goja"
	"github.com/Mzack9999/goja_nodejs/require"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
)

type Objects map[string]interface{}

type Runtime interface {
	Set(string, interface{}) error
}

type Object interface {
	Set(string, interface{})
	Get(string) interface{}
}

type Module interface {
	Name() string
	Set(objects Objects) Module
	Enable(Runtime)
	Register() Module
}

type GojaModule struct {
	name string
	sets map[string]interface{}
	once sync.Once
}

func NewGojaModule(name string) Module {
	return &GojaModule{
		name: name,
		sets: make(map[string]interface{}),
	}
}

func (p *GojaModule) String() string {
	return p.name
}

func (p *GojaModule) Name() string {
	return p.name
}

// wrapModuleFunc wraps a Go function with context injection for modules
// nolint
func wrapModuleFunc(runtime *goja.Runtime, fn interface{}) interface{} {
	fnType := reflect.TypeOf(fn)
	if fnType.Kind() != reflect.Func {
		return fn
	}

	// Only wrap if first parameter is context.Context
	if fnType.NumIn() == 0 || fnType.In(0) != reflect.TypeOf((*context.Context)(nil)).Elem() {
		return fn // Return original function unchanged if it doesn't have context.Context as first arg
	}

	// Create input and output type slices
	inTypes := make([]reflect.Type, fnType.NumIn())
	for i := 0; i < fnType.NumIn(); i++ {
		inTypes[i] = fnType.In(i)
	}
	outTypes := make([]reflect.Type, fnType.NumOut())
	for i := 0; i < fnType.NumOut(); i++ {
		outTypes[i] = fnType.Out(i)
	}

	// Create a new function with same signature
	newFnType := reflect.FuncOf(inTypes, outTypes, fnType.IsVariadic())
	newFn := reflect.MakeFunc(newFnType, func(args []reflect.Value) []reflect.Value {
		// Get context from runtime
		var ctx context.Context
		if ctxVal := runtime.Get("context"); ctxVal != nil {
			if ctxObj, ok := ctxVal.Export().(context.Context); ok {
				ctx = ctxObj
			}
		}
		if ctx == nil {
			ctx = context.Background()
		}

		// Add execution ID to context if available
		if execID := runtime.Get("executionId"); execID != nil {
			//nolint
			ctx = context.WithValue(ctx, "executionId", execID.String())
		}

		// Replace first argument (context) with our context
		args[0] = reflect.ValueOf(ctx)

		// Call original function with modified arguments
		return reflect.ValueOf(fn).Call(args)
	})

	return newFn.Interface()
}

func (p *GojaModule) Set(objects Objects) Module {
	for k, v := range objects {
		p.sets[k] = v
	}
	return p
}

func (p *GojaModule) Require(runtime *goja.Runtime, module *goja.Object) {
	o := module.Get("exports").(*goja.Object)

	for k, v := range p.sets {
		_ = o.Set(k, v)
	}
}

func (p *GojaModule) Enable(runtime Runtime) {
	_ = runtime.Set(p.Name(), require.Require(runtime.(*goja.Runtime), p.Name()))
}

func (p *GojaModule) Register() Module {
	p.once.Do(func() {
		require.RegisterNativeModule(p.Name(), p.Require)
	})

	return p
}

// GetClassConstructor returns a constructor for any given go struct type for goja runtime
func GetClassConstructor[T any](instance *T) func(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	return func(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
		return utils.LinkConstructor[*T](call, runtime, instance)
	}
}
