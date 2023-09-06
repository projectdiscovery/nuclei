package oracle

import (
	lib_oracle "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/oracle"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/oracle")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":           func() lib_oracle.OracleClient { return lib_oracle.OracleClient{} },
			"IsOracleResponse": func() lib_oracle.IsOracleResponse { return lib_oracle.IsOracleResponse{} },

			// Types (pointer type)
			"NewClient":           func() *lib_oracle.OracleClient { return &lib_oracle.OracleClient{} },
			"NewIsOracleResponse": func() *lib_oracle.IsOracleResponse { return &lib_oracle.IsOracleResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
