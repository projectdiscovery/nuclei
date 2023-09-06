package rsync

import (
	lib_rsync "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/rsync"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
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
			"Client":          func() lib_rsync.RsyncClient { return lib_rsync.RsyncClient{} },
			"IsRsyncResponse": func() lib_rsync.IsRsyncResponse { return lib_rsync.IsRsyncResponse{} },

			// Types (pointer type)
			"NewClient":          func() *lib_rsync.RsyncClient { return &lib_rsync.RsyncClient{} },
			"NewIsRsyncResponse": func() *lib_rsync.IsRsyncResponse { return &lib_rsync.IsRsyncResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
