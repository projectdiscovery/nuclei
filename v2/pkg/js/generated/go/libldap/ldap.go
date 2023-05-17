package ldap

import (
	original_ldap "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/ldap"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/libldap")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client": func() original_ldap.Client { return original_ldap.Client{} },

			// Types (pointer type)
			"NewClient": func() *original_ldap.Client { return &original_ldap.Client{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
