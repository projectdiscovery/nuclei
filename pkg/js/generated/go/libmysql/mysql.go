package mysql

import (
	lib_mysql "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/mysql"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/mysql")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions
			"BuildDSN": lib_mysql.BuildDSN,

			// Var and consts

			// Objects / Classes
			"MySQLClient":  gojs.GetClassConstructor[lib_mysql.MySQLClient](&lib_mysql.MySQLClient{}),
			"MySQLInfo":    gojs.GetClassConstructor[lib_mysql.MySQLInfo](&lib_mysql.MySQLInfo{}),
			"MySQLOptions": gojs.GetClassConstructor[lib_mysql.MySQLOptions](&lib_mysql.MySQLOptions{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
