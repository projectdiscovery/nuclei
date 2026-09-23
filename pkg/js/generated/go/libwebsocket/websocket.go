package websocket

import (
	lib_websocket "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/websocket"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/websocket")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_websocket.NewClient,

			// Var and consts

			// Objects / Classes
			"Client":  lib_websocket.NewClient,
			"Options": gojs.GetClassConstructor[lib_websocket.Options](&lib_websocket.Options{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
