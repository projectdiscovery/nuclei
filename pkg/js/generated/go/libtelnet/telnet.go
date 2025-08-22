package telnet

import (
	lib_telnet "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/telnet"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/telnet")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"IsTelnet": lib_telnet.IsTelnet,

			// Var and consts

			// Objects / Classes
			"TelnetClient":       gojs.GetClassConstructor[lib_telnet.TelnetClient](&lib_telnet.TelnetClient{}),
			"IsTelnetResponse":   gojs.GetClassConstructor[lib_telnet.IsTelnetResponse](&lib_telnet.IsTelnetResponse{}),
			"TelnetInfoResponse": gojs.GetClassConstructor[lib_telnet.TelnetInfoResponse](&lib_telnet.TelnetInfoResponse{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
