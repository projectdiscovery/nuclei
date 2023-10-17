package telnet

import (
	lib_telnet "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/telnet"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/telnet")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"IsTelnetResponse": func() lib_telnet.IsTelnetResponse { return lib_telnet.IsTelnetResponse{} },
			"TelnetClient":     func() lib_telnet.TelnetClient { return lib_telnet.TelnetClient{} },

			// Types (pointer type)
			"NewIsTelnetResponse": func() *lib_telnet.IsTelnetResponse { return &lib_telnet.IsTelnetResponse{} },
			"NewTelnetClient":     func() *lib_telnet.TelnetClient { return &lib_telnet.TelnetClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
