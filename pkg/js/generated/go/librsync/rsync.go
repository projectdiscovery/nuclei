package rsync

import (
	lib_rsync "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/rsync"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/rsync")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"IsRsyncResponse": func() lib_rsync.IsRsyncResponse { return lib_rsync.IsRsyncResponse{} },
			"RsyncClient":     func() lib_rsync.RsyncClient { return lib_rsync.RsyncClient{} },

			// Types (pointer type)
			"NewIsRsyncResponse": func() *lib_rsync.IsRsyncResponse { return &lib_rsync.IsRsyncResponse{} },
			"NewRsyncClient":     func() *lib_rsync.RsyncClient { return &lib_rsync.RsyncClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
