package net

import (
	original_net "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/net"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libnet")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"Open":    original_net.Open,
			"OpenTLS": original_net.OpenTLS,

			// Var and consts

			// Types (value type)
			"Conn": func() original_net.Conn { return original_net.Conn{} },

			// Types (pointer type)
			"NewConn": func() *original_net.Conn { return &original_net.Conn{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
