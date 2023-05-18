package vnc

import (
	original_vnc "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/vnc"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libvnc")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":        func() original_vnc.Client { return original_vnc.Client{} },
			"IsVNCResponse": func() original_vnc.IsVNCResponse { return original_vnc.IsVNCResponse{} },

			// Types (pointer type)
			"NewClient":        func() *original_vnc.Client { return &original_vnc.Client{} },
			"NewIsVNCResponse": func() *original_vnc.IsVNCResponse { return &original_vnc.IsVNCResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
