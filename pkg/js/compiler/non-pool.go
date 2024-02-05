package compiler

import (
	"sync"

	"github.com/dop251/goja"
	"github.com/remeh/sizedwaitgroup"
)

var (
	ephemeraljsc    = sizedwaitgroup.New(NonPoolingVMConcurrency)
	lazyFixedSgInit = sync.OnceFunc(func() {
		ephemeraljsc = sizedwaitgroup.New(NonPoolingVMConcurrency)
	})
)

func executeWithoutPooling(p *goja.Program, args *ExecuteArgs, opts *ExecuteOptions) (result goja.Value, err error) {
	lazyFixedSgInit()
	ephemeraljsc.Add()
	defer ephemeraljsc.Done()
	runtime := createNewRuntime()
	return executeWithRuntime(runtime, p, args, opts)
}
