package vnc

import (
	lib_vnc "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/vnc"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/vnc")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"IsVNCResponse": gojs.GetClassConstructor[lib_vnc.IsVNCResponse](&lib_vnc.IsVNCResponse{}),
			"VNCClient":     gojs.GetClassConstructor[lib_vnc.VNCClient](&lib_vnc.VNCClient{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
