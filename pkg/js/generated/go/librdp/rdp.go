package rdp

import (
	lib_rdp "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/rdp"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
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
			"IsRDPResponse":        func() lib_rdp.IsRDPResponse { return lib_rdp.IsRDPResponse{} },
			"RDPClient":            func() lib_rdp.RDPClient { return lib_rdp.RDPClient{} },

			// Types (pointer type)
			"NewCheckRDPAuthResponse": func() *lib_rdp.CheckRDPAuthResponse { return &lib_rdp.CheckRDPAuthResponse{} },
			"NewIsRDPResponse":        func() *lib_rdp.IsRDPResponse { return &lib_rdp.IsRDPResponse{} },
			"NewRDPClient":            func() *lib_rdp.RDPClient { return &lib_rdp.RDPClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
