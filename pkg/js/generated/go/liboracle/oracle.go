package oracle

import (
	lib_oracle "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/oracle"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/oracle")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"IsOracle": lib_oracle.IsOracle,

			// Var and consts

			// Objects / Classes
			"IsOracleResponse": gojs.GetClassConstructor[lib_oracle.IsOracleResponse](&lib_oracle.IsOracleResponse{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
