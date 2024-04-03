package compiler

import (
	"math"
	"sync"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/cruisecontrol"
	syncutil "github.com/projectdiscovery/utils/sync"
	"github.com/projectdiscovery/utils/sync/sizedpool"
)

type JsPool struct {
	CruiseControl *cruisecontrol.CruiseControl

	ephemeraljsc  *syncutil.AdaptiveWaitGroup
	pooljsc       *syncutil.AdaptiveWaitGroup
	sizedGojaPool *sizedpool.SizedPool[*goja.Runtime]
}

func NewPool(cruiseControl *cruisecontrol.CruiseControl) (*JsPool, error) {
	ephemeraljsc, _ := syncutil.New(syncutil.WithSize(cruiseControl.Settings.Javascript.Concurrency.NotPooled))
	pooljsc, _ := syncutil.New(syncutil.WithSize(cruiseControl.Settings.Javascript.Concurrency.Pooled))
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

	return &JsPool{CruiseControl: cruiseControl, ephemeraljsc: ephemeraljsc, pooljsc: pooljsc, sizedGojaPool: sizedGojaPool}, nil
}
