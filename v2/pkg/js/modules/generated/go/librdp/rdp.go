package rdp

import (
	lib_rdp "github.com/projectdiscovery/nuclei/v2/pkg/js/modules/libs/rdp"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/modules/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/rdp")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"CheckRDPAuthResponse": func() lib_rdp.CheckRDPAuthResponse { return lib_rdp.CheckRDPAuthResponse{} },
			"Client":               func() lib_rdp.Client { return lib_rdp.Client{} },
			"IsRDPResponse":        func() lib_rdp.IsRDPResponse { return lib_rdp.IsRDPResponse{} },

			// Types (pointer type)
			"NewCheckRDPAuthResponse": func() *lib_rdp.CheckRDPAuthResponse { return &lib_rdp.CheckRDPAuthResponse{} },
			"NewClient":               func() *lib_rdp.Client { return &lib_rdp.Client{} },
			"NewIsRDPResponse":        func() *lib_rdp.IsRDPResponse { return &lib_rdp.IsRDPResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
