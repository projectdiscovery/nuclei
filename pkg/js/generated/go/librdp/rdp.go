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
			"CheckRDPAuth": lib_rdp.CheckRDPAuth,
			"IsRDP":        lib_rdp.IsRDP,

			// Var and consts

			// Objects / Classes
			"CheckRDPAuthResponse": gojs.GetClassConstructor[lib_rdp.CheckRDPAuthResponse](&lib_rdp.CheckRDPAuthResponse{}),
			"IsRDPResponse":        gojs.GetClassConstructor[lib_rdp.IsRDPResponse](&lib_rdp.IsRDPResponse{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
