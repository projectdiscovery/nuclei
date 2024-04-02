package compiler

import (
	"github.com/dop251/goja"
)

func (jsp *JsPool) executeWithoutPooling(p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (result goja.Value, err error) {
	// check if the pool should be resized
	if jsp.ephemeraljsc.Size != NonPoolingVMConcurrency {
		jsp.ephemeraljsc.Resize(NonPoolingVMConcurrency)
	}

	jsp.ephemeraljsc.Add()
	defer jsp.ephemeraljsc.Done()

	runtime := createNewRuntime()

	return jsp.executeWithRuntime(runtime, p, args, opts)
}
