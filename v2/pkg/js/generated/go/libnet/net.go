package net

import (
	lib_net "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/net"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/net")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"Open":    lib_net.Open,
			"OpenTLS": lib_net.OpenTLS,

			// Var and consts

			// Types (value type)
			"Conn": func() lib_net.Conn { return lib_net.Conn{} },

			// Types (pointer type)
			"NewConn": func() *lib_net.Conn { return &lib_net.Conn{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
