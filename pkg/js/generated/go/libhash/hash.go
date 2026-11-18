package hash

import (
	lib_hash "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/hash"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/hash")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"New": lib_hash.New,

			// Var and consts

			// Objects / Classes
			"Hash": gojs.GetClassConstructor[lib_hash.Hash](&lib_hash.Hash{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
