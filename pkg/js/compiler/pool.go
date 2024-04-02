package compiler

import (
	"math"
	"sync"

	"github.com/dop251/goja"
	syncutil "github.com/projectdiscovery/utils/sync"
	"github.com/projectdiscovery/utils/sync/sizedpool"
)

type JsPool struct {
	ephemeraljsc  *syncutil.AdaptiveWaitGroup
	pooljsc       *syncutil.AdaptiveWaitGroup
	sizedGojaPool *sizedpool.SizedPool[*goja.Runtime]
}

func NewPool() (*JsPool, error) {
	ephemeraljsc, _ := syncutil.New(syncutil.WithSize(NonPoolingVMConcurrency))
	pooljsc, _ := syncutil.New(syncutil.WithSize(PoolingJsVmConcurrency))
	gojapool := &sync.Pool{
		New: func() interface{} {
			return createNewRuntime()
		},
	}

	var err error
	sizedGojaPool, err := sizedpool.New[*goja.Runtime](sizedpool.WithPool[*goja.Runtime](gojapool), sizedpool.WithSize[*goja.Runtime](math.MaxInt32))
	if err != nil {
		return nil, err
	}

	return &JsPool{ephemeraljsc: ephemeraljsc, pooljsc: pooljsc, sizedGojaPool: sizedGojaPool}, nil
}
