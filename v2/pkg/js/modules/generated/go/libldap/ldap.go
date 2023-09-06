package ldap

import (
	lib_ldap "github.com/projectdiscovery/nuclei/v2/pkg/js/libs/ldap"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v2/pkg/js/gojs"
)

var (
	module = gojs.NewGojaModule("nuclei/ldap")
)

func init() {
	module.Set(
		gojs.Objects{
			// Functions

			// Var and consts

			// Types (value type)
			"Client":       func() lib_ldap.LdapClient { return lib_ldap.LdapClient{} },
			"LDAPMetadata": func() lib_ldap.LDAPMetadata { return lib_ldap.LDAPMetadata{} },

			// Types (pointer type)
			"NewClient":       func() *lib_ldap.LdapClient { return &lib_ldap.LdapClient{} },
			"NewLDAPMetadata": func() *lib_ldap.LDAPMetadata { return &lib_ldap.LDAPMetadata{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
