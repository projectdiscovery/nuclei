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
			"Close":    original_net.Close,
			"Open":     original_net.Open,
			"Recv":     original_net.Recv,
			"Send":     original_net.Send,
			"SendRecv": original_net.SendRecv,

			// Var and consts

			// Types (value type)

			// Types (pointer type)
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
