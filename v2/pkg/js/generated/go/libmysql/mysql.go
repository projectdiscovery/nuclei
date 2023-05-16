package mysql

import (
	original_mysql "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/mysql"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libmysql")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client": func() original_mysql.Client { return original_mysql.Client{} },

			// Types (pointer type)
			"NewClient": func() *original_mysql.Client { return &original_mysql.Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
