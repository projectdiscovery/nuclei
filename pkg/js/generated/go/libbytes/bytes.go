package bytes

import (
	lib_bytes "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/bytes"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/bytes")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewBuffer": lib_bytes.NewBuffer,

			// Var and consts

			// Objects / Classes
			"Buffer": lib_bytes.NewBuffer,
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
