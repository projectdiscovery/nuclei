package vnc

import (
	lib_vnc "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/vnc"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/vnc")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":        func() lib_vnc.Client { return lib_vnc.Client{} },
			"IsVNCResponse": func() lib_vnc.IsVNCResponse { return lib_vnc.IsVNCResponse{} },

			// Types (pointer type)
			"NewClient":        func() *lib_vnc.Client { return &lib_vnc.Client{} },
			"NewIsVNCResponse": func() *lib_vnc.IsVNCResponse { return &lib_vnc.IsVNCResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
