package rsync

import (
	original_rsync "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/rsync"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/librsync")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":          func() original_rsync.Client { return original_rsync.Client{} },
			"IsRsyncResponse": func() original_rsync.IsRsyncResponse { return original_rsync.IsRsyncResponse{} },

			// Types (pointer type)
			"NewClient":          func() *original_rsync.Client { return &original_rsync.Client{} },
			"NewIsRsyncResponse": func() *original_rsync.IsRsyncResponse { return &original_rsync.IsRsyncResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
