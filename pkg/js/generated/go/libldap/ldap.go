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
			"DecodeADTimestamp":   lib_ldap.DecodeADTimestamp,
			"DecodeSID":           lib_ldap.DecodeSID,
			"DecodeZuluTimestamp": lib_ldap.DecodeZuluTimestamp,
			"JoinFilters":         lib_ldap.JoinFilters,
			"NegativeFilter":      lib_ldap.NegativeFilter,
			"NewClient":           lib_ldap.NewClient,

			// Var and consts
			"FilterAccountDisabled":            lib_ldap.FilterAccountDisabled,
			"FilterAccountEnabled":             lib_ldap.FilterAccountEnabled,
			"FilterCanSendEncryptedPassword":   lib_ldap.FilterCanSendEncryptedPassword,
			"FilterDontExpirePassword":         lib_ldap.FilterDontExpirePassword,
			"FilterDontRequirePreauth":         lib_ldap.FilterDontRequirePreauth,
			"FilterHasServicePrincipalName":    lib_ldap.FilterHasServicePrincipalName,
			"FilterHomedirRequired":            lib_ldap.FilterHomedirRequired,
			"FilterInterdomainTrustAccount":    lib_ldap.FilterInterdomainTrustAccount,
			"FilterIsAdmin":                    lib_ldap.FilterIsAdmin,
			"FilterIsComputer":                 lib_ldap.FilterIsComputer,
			"FilterIsDuplicateAccount":         lib_ldap.FilterIsDuplicateAccount,
			"FilterIsGroup":                    lib_ldap.FilterIsGroup,
			"FilterIsNormalAccount":            lib_ldap.FilterIsNormalAccount,
			"FilterIsPerson":                   lib_ldap.FilterIsPerson,
			"FilterLockout":                    lib_ldap.FilterLockout,
			"FilterLogonScript":                lib_ldap.FilterLogonScript,
			"FilterMnsLogonAccount":            lib_ldap.FilterMnsLogonAccount,
			"FilterNotDelegated":               lib_ldap.FilterNotDelegated,
			"FilterPartialSecretsAccount":      lib_ldap.FilterPartialSecretsAccount,
			"FilterPasswordCantChange":         lib_ldap.FilterPasswordCantChange,
			"FilterPasswordExpired":            lib_ldap.FilterPasswordExpired,
			"FilterPasswordNotRequired":        lib_ldap.FilterPasswordNotRequired,
			"FilterServerTrustAccount":         lib_ldap.FilterServerTrustAccount,
			"FilterSmartCardRequired":          lib_ldap.FilterSmartCardRequired,
			"FilterTrustedForDelegation":       lib_ldap.FilterTrustedForDelegation,
			"FilterTrustedToAuthForDelegation": lib_ldap.FilterTrustedToAuthForDelegation,
			"FilterUseDesKeyOnly":              lib_ldap.FilterUseDesKeyOnly,
			"FilterWorkstationTrustAccount":    lib_ldap.FilterWorkstationTrustAccount,

			// Objects / Classes
			"Client":         lib_ldap.NewClient,
			"Config":         gojs.GetClassConstructor[lib_ldap.Config](&lib_ldap.Config{}),
			"LdapAttributes": gojs.GetClassConstructor[lib_ldap.LdapAttributes](&lib_ldap.LdapAttributes{}),
			"LdapEntry":      gojs.GetClassConstructor[lib_ldap.LdapEntry](&lib_ldap.LdapEntry{}),
			"Metadata":       gojs.GetClassConstructor[lib_ldap.Metadata](&lib_ldap.Metadata{}),
			"SearchResult":   gojs.GetClassConstructor[lib_ldap.SearchResult](&lib_ldap.SearchResult{}),
		},
	).Register()
}

func Enable(runtime *goja.Runtime) {
	module.Enable(runtime)
}
