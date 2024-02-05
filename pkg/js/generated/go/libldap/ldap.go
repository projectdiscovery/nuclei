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
			"JoinFilters":         func(f ...string) string { return lib_ldap.JoinFilters(f...) },
			"NegativeFilter":      func(f string) string { return lib_ldap.NegativeFilter(f) },
			"DecodeSID":           func(s string) string { return lib_ldap.DecodeSID(s) },
			"DecodeADTimestamp":   func(s string) string { return lib_ldap.DecodeADTimestamp(s) },
			"DecodeZuluTimestamp": func(s string) string { return lib_ldap.DecodeZuluTimestamp(s) },

			// Var and consts
			"FilterIsPerson":                   func() string { return lib_ldap.FilterIsPerson },
			"FilterIsGroup":                    func() string { return lib_ldap.FilterIsGroup },
			"FilterIsComputer":                 func() string { return lib_ldap.FilterIsComputer },
			"FilterIsAdmin":                    func() string { return lib_ldap.FilterIsAdmin },
			"FilterLogonScript":                func() string { return lib_ldap.FilterLogonScript },
			"FilterAccountDisabled":            func() string { return lib_ldap.FilterAccountDisabled },
			"FilterAccountEnabled":             func() string { return lib_ldap.FilterAccountEnabled },
			"FilterHomedirRequired":            func() string { return lib_ldap.FilterHomedirRequired },
			"FilterLockout":                    func() string { return lib_ldap.FilterLockout },
			"FilterPasswordNotRequired":        func() string { return lib_ldap.FilterPasswordNotRequired },
			"FilterPasswordCantChange":         func() string { return lib_ldap.FilterPasswordCantChange },
			"FilterCanSendEncryptedPassword":   func() string { return lib_ldap.FilterCanSendEncryptedPassword },
			"FilterIsDuplicateAccount":         func() string { return lib_ldap.FilterIsDuplicateAccount },
			"FilterIsNormalAccount":            func() string { return lib_ldap.FilterIsNormalAccount },
			"FilterInterdomainTrustAccount":    func() string { return lib_ldap.FilterInterdomainTrustAccount },
			"FilterWorkstationTrustAccount":    func() string { return lib_ldap.FilterWorkstationTrustAccount },
			"FilterServerTrustAccount":         func() string { return lib_ldap.FilterServerTrustAccount },
			"FilterDontExpirePassword":         func() string { return lib_ldap.FilterDontExpirePassword },
			"FilterMnsLogonAccount":            func() string { return lib_ldap.FilterMnsLogonAccount },
			"FilterSmartCardRequired":          func() string { return lib_ldap.FilterSmartCardRequired },
			"FilterTrustedForDelegation":       func() string { return lib_ldap.FilterTrustedForDelegation },
			"FilterNotDelegated":               func() string { return lib_ldap.FilterNotDelegated },
			"FilterUseDesKeyOnly":              func() string { return lib_ldap.FilterUseDesKeyOnly },
			"FilterDontRequirePreauth":         func() string { return lib_ldap.FilterDontRequirePreauth },
			"FilterPasswordExpired":            func() string { return lib_ldap.FilterPasswordExpired },
			"FilterTrustedToAuthForDelegation": func() string { return lib_ldap.FilterTrustedToAuthForDelegation },
			"FilterPartialSecretsAccount":      func() string { return lib_ldap.FilterPartialSecretsAccount },

			// Types (value type)
			"Metadata":   func() lib_ldap.Metadata { return lib_ldap.Metadata{} },
			"LdapClient": lib_ldap.NewClient,

			// Types (pointer type)
			// "NewMetadata":   func() *lib_ldap.Metadata { return &lib_ldap.Metadata{} },
			// "NewLdapClient": func() *lib_ldap.LdapClient { return &lib_ldap.LdapClient{} },
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
