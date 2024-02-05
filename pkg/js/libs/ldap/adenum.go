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

// JoinFilters joins multiple filters into a single filter
func JoinFilters(filters ...string) string {
	var builder strings.Builder
	builder.WriteString("(&")
	for _, s := range filters {
		builder.WriteString(s)
	}
	builder.WriteString(")")
	return builder.String()
}

// NegativeFilter returns a negative filter for a given filter
func NegativeFilter(filter string) string {
	return fmt.Sprintf("(!%s)", filter)
}

// ADObject represents an Active Directory object
type ADObject struct {
	DistinguishedName    string
	SAMAccountName       string
	PWDLastSet           string
	LastLogon            string
	MemberOf             []string
	ServicePrincipalName []string
}

// FindADObjects finds AD objects based on a filter
// and returns them as a list of ADObject
// @param filter: string
// @return []ADObject
func (c *Client) FindADObjects(filter string) []ADObject {
	c.nj.Require(c.conn != nil, "no existing connection")
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

	res, err := c.conn.Search(sr)
	c.nj.HandleError(err, "ldap search request failed")

	var objects []ADObject
	for _, obj := range res.Entries {
		objects = append(objects, ADObject{
			DistinguishedName:    obj.GetAttributeValue("distinguishedName"),
			SAMAccountName:       obj.GetAttributeValue("sAMAccountName"),
			PWDLastSet:           DecodeADTimestamp(obj.GetAttributeValue("pwdLastSet")),
			LastLogon:            DecodeADTimestamp(obj.GetAttributeValue("lastLogon")),
			MemberOf:             obj.GetAttributeValues("memberOf"),
			ServicePrincipalName: obj.GetAttributeValues("servicePrincipalName"),
		})
	}
	return objects
}

// GetADUsers returns all AD users
// using FilterIsPerson filter query
// @return []ADObject
func (c *Client) GetADUsers() []ADObject {
	return c.FindADObjects(FilterIsPerson)
}

// GetADActiveUsers returns all AD users
// using FilterIsPerson and FilterAccountEnabled filter query
// @return []ADObject
func (c *Client) GetADActiveUsers() []ADObject {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled))
}

// GetAdUserWithNeverExpiringPasswords returns all AD users
// using FilterIsPerson and FilterDontExpirePassword filter query
// @return []ADObject
func (c *Client) GetADUserWithNeverExpiringPasswords() []ADObject {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterDontExpirePassword))
}

// GetADUserTrustedForDelegation returns all AD users that are trusted for delegation
// using FilterIsPerson and FilterTrustedForDelegation filter query
// @return []ADObject
func (c *Client) GetADUserTrustedForDelegation() []ADObject {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterTrustedForDelegation))
}

// GetADUserWithPasswordNotRequired returns all AD users that do not require a password
// using FilterIsPerson and FilterPasswordNotRequired filter query
// @return []ADObject
func (c *Client) GetADUserWithPasswordNotRequired() []ADObject {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterPasswordNotRequired))
}

// GetADGroups returns all AD groups
// using FilterIsGroup filter query
// @return []ADObject
func (c *Client) GetADGroups() []ADObject {
	return c.FindADObjects(FilterIsGroup)
}

// GetADDCList returns all AD domain controllers
// using FilterIsComputer, FilterAccountEnabled and FilterServerTrustAccount filter query
// @return []ADObject
func (c *Client) GetADDCList() []ADObject {
	return c.FindADObjects(JoinFilters(FilterIsComputer, FilterAccountEnabled, FilterServerTrustAccount))
}

// GetADAdmins returns all AD admins
// using FilterIsPerson, FilterAccountEnabled and FilterIsAdmin filter query
// @return []ADObject
func (c *Client) GetADAdmins() []ADObject {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled, FilterIsAdmin))
}

// GetADUserKerberoastable returns all AD users that are kerberoastable
// using FilterIsPerson, FilterAccountEnabled and FilterHasServicePrincipalName filter query
// @return []ADObject
func (c *Client) GetADUserKerberoastable() []ADObject {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled, FilterHasServicePrincipalName))
}

// GetADDomainSID returns the SID of the AD domain
// @return string
func (c *Client) GetADDomainSID() string {
	r := c.Search(FilterServerTrustAccount, "objectSid")
	c.nj.Require(len(r) > 0, "no result from GetADDomainSID query")
	c.nj.Require(len(r[0]["objectSid"]) > 0, "could not grab DomainSID")
	return DecodeSID(r[0]["objectSid"][0])
}
