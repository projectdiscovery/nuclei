package telnet

import (
	lib_telnet "github.com/projectdiscovery/nuclei/v2/pkg/js/modules/libs/telnet"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/modules/gojs"
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
			"Client":           func() lib_telnet.Client { return lib_telnet.Client{} },
			"IsTelnetResponse": func() lib_telnet.IsTelnetResponse { return lib_telnet.IsTelnetResponse{} },

			// Types (pointer type)
			"NewClient":           func() *lib_telnet.Client { return &lib_telnet.Client{} },
			"NewIsTelnetResponse": func() *lib_telnet.IsTelnetResponse { return &lib_telnet.IsTelnetResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
