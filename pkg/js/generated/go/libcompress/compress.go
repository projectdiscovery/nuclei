package compress

import (
	lib_compress "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/compress"

	"github.com/projectdiscovery/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/compress")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"NewDecoder": lib_compress.NewDecoder,

			// Var and consts

			// Objects / Classes
			"Decoder": gojs.GetClassConstructor[lib_compress.Decoder](&lib_compress.Decoder{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
