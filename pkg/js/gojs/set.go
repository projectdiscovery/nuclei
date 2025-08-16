package gojs

import (
	"context"
	"reflect"

	"github.com/Mzack9999/goja"
	errorutil "github.com/projectdiscovery/utils/errors"
)

var (
	ErrInvalidFuncOpts = errorutil.NewWithFmt("invalid function options: %v")
	ErrNilRuntime      = errorutil.New("runtime is nil")
)

type FuncOpts struct {
	Name        string
	Signatures  []string
	Description string
	FuncDecl    interface{}
}

// valid checks if the function options are valid
func (f *FuncOpts) valid() bool {
	return f.Name != "" && f.FuncDecl != nil && len(f.Signatures) > 0 && f.Description != ""
}

// wrapWithContext wraps a Go function with context injection
// nolint
func wrapWithContext(runtime *goja.Runtime, fn interface{}) interface{} {
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
			ctx = context.WithValue(ctx, "executionId", execID.String())
		}

		// Replace first argument (context) with our context
		args[0] = reflect.ValueOf(ctx)

		// Call original function with modified arguments
		return reflect.ValueOf(fn).Call(args)
	})

	return newFn.Interface()
}

// RegisterFunc registers a function with given name, signatures and description
func RegisterFuncWithSignature(runtime *goja.Runtime, opts FuncOpts) error {
	if runtime == nil {
		return ErrNilRuntime
	}
	if !opts.valid() {
		return ErrInvalidFuncOpts.Msgf("name: %s, signatures: %v, description: %s", opts.Name, opts.Signatures, opts.Description)
	}

	// Wrap the function with context injection
	// wrappedFn := wrapWithContext(runtime, opts.FuncDecl)
	return runtime.Set(opts.Name, opts.FuncDecl /* wrappedFn */)
}
