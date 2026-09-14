package grpc

import (
	lib_grpc "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/grpc"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/grpc")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewClient": lib_grpc.NewClient,

			// Var and consts

			// Objects / Classes
			"Client":  lib_grpc.NewClient,
			"Options": gojs.GetClassConstructor[lib_grpc.Options](&lib_grpc.Options{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
