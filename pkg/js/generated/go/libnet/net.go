package net

import (
	lib_net "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/net"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
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
			"NetConn": func() lib_net.NetConn { return lib_net.NetConn{} },

			// Types (pointer type)
			"NewNetConn": func() *lib_net.NetConn { return &lib_net.NetConn{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
