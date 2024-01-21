package ldap

import (
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

// LDAP makes you search using an OID
// http://oid-info.com/get/1.2.840.113556.1.4.803
//
// The one for the userAccountControl in MS Active Directory is
// 1.2.840.113556.1.4.803 (LDAP_MATCHING_RULE_BIT_AND)
//
// We can look at the enabled flags using a query like (!(userAccountControl:1.2.840.113556.1.4.803:=2))
//
// https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
const (
	FilterIsPerson                   = "(objectCategory=person)"
	FilterIsGroup                    = "(objectCategory=group)"
	FilterIsComputer                 = "(objectCategory=computer)"
	FilterIsAdmin                    = "(adminCount=1)"
	FilterHasServicePrincipalName    = "(servicePrincipalName=*)"
	FilterLogonScript                = "(userAccountControl:1.2.840.113556.1.4.803:=1)"        // The logon script will be run.
	FilterAccountDisabled            = "(userAccountControl:1.2.840.113556.1.4.803:=2)"        // The user account is disabled.
	FilterAccountEnabled             = "(!(userAccountControl:1.2.840.113556.1.4.803:=2))"     // The user account is enabled.
	FilterHomedirRequired            = "(userAccountControl:1.2.840.113556.1.4.803:=8)"        // The home folder is required.
	FilterLockout                    = "(userAccountControl:1.2.840.113556.1.4.803:=16)"       // The user is locked out.
	FilterPasswordNotRequired        = "(userAccountControl:1.2.840.113556.1.4.803:=32)"       // No password is required.
	FilterPasswordCantChange         = "(userAccountControl:1.2.840.113556.1.4.803:=64)"       // The user can't change the password.
	FilterCanSendEncryptedPassword   = "(userAccountControl:1.2.840.113556.1.4.803:=128)"      // The user can send an encrypted password.
	FilterIsDuplicateAccount         = "(userAccountControl:1.2.840.113556.1.4.803:=256)"      // It's an account for users whose primary account is in another domain.
	FilterIsNormalAccount            = "(userAccountControl:1.2.840.113556.1.4.803:=512)"      // It's a default account type that represents a typical user.
	FilterInterdomainTrustAccount    = "(userAccountControl:1.2.840.113556.1.4.803:=2048)"     // It's a permit to trust an account for a system domain that trusts other domains.
	FilterWorkstationTrustAccount    = "(userAccountControl:1.2.840.113556.1.4.803:=4096)"     // It's a computer account for a computer that is running old Windows builds.
	FilterServerTrustAccount         = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"     // It's a computer account for a domain controller that is a member of this domain.
	FilterDontExpirePassword         = "(userAccountControl:1.2.840.113556.1.4.803:=65536)"    // Represents the password, which should never expire on the account.
	FilterMnsLogonAccount            = "(userAccountControl:1.2.840.113556.1.4.803:=131072)"   // It's an MNS logon account.
	FilterSmartCardRequired          = "(userAccountControl:1.2.840.113556.1.4.803:=262144)"   // When this flag is set, it forces the user to log on by using a smart card.
	FilterTrustedForDelegation       = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"   // When this flag is set, the service account (the user or computer account) under which a service runs is trusted for Kerberos delegation.
	FilterNotDelegated               = "(userAccountControl:1.2.840.113556.1.4.803:=1048576)"  // When this flag is set, the security context of the user isn't delegated to a service even if the service account is set as trusted for Kerberos delegation.
	FilterUseDesKeyOnly              = "(userAccountControl:1.2.840.113556.1.4.803:=2097152)"  // Restrict this principal to use only Data Encryption Standard (DES) encryption types for keys.
	FilterDontRequirePreauth         = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"  // This account doesn't require Kerberos pre-authentication for logging on.
	FilterPasswordExpired            = "(userAccountControl:1.2.840.113556.1.4.803:=8388608)"  // The user's password has expired.
	FilterTrustedToAuthForDelegation = "(userAccountControl:1.2.840.113556.1.4.803:=16777216)" // The account is enabled for delegation.
	FilterPartialSecretsAccount      = "(userAccountControl:1.2.840.113556.1.4.803:=67108864)" // The account is a read-only domain controller (RODC).

)

func JoinFilters(filters ...string) string {
	var builder strings.Builder
	builder.WriteString("(&")
	for _, s := range filters {
		builder.WriteString(s)
	}
	builder.WriteString(")")
	return builder.String()
}

func NegativeFilter(filter string) string {
	return fmt.Sprintf("(!%s)", filter)
}

type ADObject struct {
	DistinguishedName    string
	SAMAccountName       string
	PWDLastSet           string
	LastLogon            string
	MemberOf             []string
	ServicePrincipalName []string
}

func (c *LdapClient) FindADObjects(filter string) ([]ADObject, error) {
	sr := ldap.NewSearchRequest(
		c.BaseDN, ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{
			"distinguishedName",
			"sAMAccountName",
			"pwdLastSet",
			"lastLogon",
			"memberOf",
			"servicePrincipalName",
		},
		nil,
	)

	res, err := c.Conn.Search(sr)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no object returned from query")
	}

	var objects []ADObject
	for _, obj := range res.Entries {
		objects = append(objects, ADObject{
			DistinguishedName:    obj.GetAttributeValue("distinguishedName"),
			SAMAccountName:       obj.GetAttributeValue("sAMAccountName"),
			PWDLastSet:           obj.GetAttributeValue("pwdLastSet"),
			LastLogon:            obj.GetAttributeValue("lastLogon"),
			MemberOf:             obj.GetAttributeValues("memberOf"),
			ServicePrincipalName: obj.GetAttributeValues("servicePrincipalName"),
		})
	}
	return objects, nil
}

func (c *LdapClient) GetADUsers() ([]ADObject, error) {
	return c.FindADObjects(FilterIsPerson)
}

func (c *LdapClient) GetADActiveUsers() ([]ADObject, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled))
}

func (c *LdapClient) GetADUserWithNeverExpiringPasswords() ([]ADObject, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterDontExpirePassword))
}

func (c *LdapClient) GetADUserTrustedForDelegation() ([]ADObject, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterTrustedForDelegation))
}

func (c *LdapClient) GetADUserWithPasswordNotRequired() ([]ADObject, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterPasswordNotRequired))
}

func (c *LdapClient) GetADGroups() ([]ADObject, error) {
	return c.FindADObjects(FilterIsGroup)
}

func (c *LdapClient) GetADDCList() ([]ADObject, error) {
	return c.FindADObjects(JoinFilters(FilterIsComputer, FilterAccountEnabled, FilterServerTrustAccount))
}

func (c *LdapClient) GetADAdmins() ([]ADObject, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled, FilterIsAdmin))
}

func (c *LdapClient) GetADUserKerberoastable() ([]ADObject, error) {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled, FilterHasServicePrincipalName))
}
