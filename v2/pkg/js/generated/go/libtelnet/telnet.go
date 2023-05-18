package telnet

import (
	original_telnet "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/telnet"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libtelnet")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":           func() original_telnet.Client { return original_telnet.Client{} },
			"IsTelnetResponse": func() original_telnet.IsTelnetResponse { return original_telnet.IsTelnetResponse{} },

			// Types (pointer type)
			"NewClient":           func() *original_telnet.Client { return &original_telnet.Client{} },
			"NewIsTelnetResponse": func() *original_telnet.IsTelnetResponse { return &original_telnet.IsTelnetResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
