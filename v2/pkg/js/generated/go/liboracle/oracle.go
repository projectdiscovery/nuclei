package oracle

import (
	original_oracle "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/oracle"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/liboracle")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":           func() original_oracle.Client { return original_oracle.Client{} },
			"IsOracleResponse": func() original_oracle.IsOracleResponse { return original_oracle.IsOracleResponse{} },

			// Types (pointer type)
			"NewClient":           func() *original_oracle.Client { return &original_oracle.Client{} },
			"NewIsOracleResponse": func() *original_oracle.IsOracleResponse { return &original_oracle.IsOracleResponse{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
