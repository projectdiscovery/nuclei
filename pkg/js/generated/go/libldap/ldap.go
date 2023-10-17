package ldap

import (
	lib_ldap "github.com/projectdiscovery/nuclei/v3/pkg/js/libs/ldap"

	"github.com/dop251/goja"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/gojs"
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
			"LDAPMetadata": func() lib_ldap.LDAPMetadata { return lib_ldap.LDAPMetadata{} },
			"LdapClient":   func() lib_ldap.LdapClient { return lib_ldap.LdapClient{} },

			// Types (pointer type)
			"NewLDAPMetadata": func() *lib_ldap.LDAPMetadata { return &lib_ldap.LDAPMetadata{} },
			"NewLdapClient":   func() *lib_ldap.LdapClient { return &lib_ldap.LdapClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
