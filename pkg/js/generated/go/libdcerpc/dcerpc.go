package dcerpc

import (
	lib_dcerpc "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/dcerpc"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/dcerpc")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Objects / Classes
			"Client":        lib_dcerpc.NewClient,
			"Endpoint":      gojs.GetClassConstructor[lib_dcerpc.Endpoint](&lib_dcerpc.Endpoint{}),
			"DomainUser":    gojs.GetClassConstructor[lib_dcerpc.DomainUser](&lib_dcerpc.DomainUser{}),
			"LookupResult":  gojs.GetClassConstructor[lib_dcerpc.LookupResult](&lib_dcerpc.LookupResult{}),
			"SmbExecResult": gojs.GetClassConstructor[lib_dcerpc.SmbExecResult](&lib_dcerpc.SmbExecResult{}),
			"AtExecResult":  gojs.GetClassConstructor[lib_dcerpc.AtExecResult](&lib_dcerpc.AtExecResult{}),
			"WmiExecResult": gojs.GetClassConstructor[lib_dcerpc.WmiExecResult](&lib_dcerpc.WmiExecResult{}),
			"FileEntry":     gojs.GetClassConstructor[lib_dcerpc.FileEntry](&lib_dcerpc.FileEntry{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
