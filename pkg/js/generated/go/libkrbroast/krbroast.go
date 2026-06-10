package krbroast

import (
	lib_krbroast "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/krbroast"

	"github.com/Mzack9999/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/krbroast")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"ASRepRoast":  lib_krbroast.ASRepRoast,
			"Kerberoast":  lib_krbroast.Kerberoast,

			// Var and consts

			// Objects / Classes
			"ASRepRoastRequest": gojs.GetClassConstructor[lib_krbroast.ASRepRoastRequest](&lib_krbroast.ASRepRoastRequest{}),
			"KerberoastRequest": gojs.GetClassConstructor[lib_krbroast.KerberoastRequest](&lib_krbroast.KerberoastRequest{}),
			"KerberoastResult":  gojs.GetClassConstructor[lib_krbroast.KerberoastResult](&lib_krbroast.KerberoastResult{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
