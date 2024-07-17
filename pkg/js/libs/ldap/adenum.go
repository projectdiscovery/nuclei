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
	FilterIsPerson                   = "(objectCategory=person)"                               // The object is a person.
	FilterIsGroup                    = "(objectCategory=group)"                                // The object is a group.
	FilterIsComputer                 = "(objectCategory=computer)"                             // The object is a computer.
	FilterIsAdmin                    = "(adminCount=1)"                                        // The object is an admin.
	FilterHasServicePrincipalName    = "(servicePrincipalName=*)"                              // The object has a service principal name.
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
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const filter = ldap.JoinFilters(ldap.FilterIsPerson, ldap.FilterAccountEnabled);
// ```
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
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const filter = ldap.NegativeFilter(ldap.FilterIsPerson);
// ```
func NegativeFilter(filter string) string {
	return fmt.Sprintf("(!%s)", filter)
}

// FindADObjects finds AD objects based on a filter
// and returns them as a list of ADObject
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const users = client.FindADObjects(ldap.FilterIsPerson);
// log(to_json(users));
// ```
func (c *Client) FindADObjects(filter string) SearchResult {
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
	return *getSearchResult(res)
}

// GetADUsers returns all AD users
// using FilterIsPerson filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const users = client.GetADUsers();
// log(to_json(users));
// ```
func (c *Client) GetADUsers() SearchResult {
	return c.FindADObjects(FilterIsPerson)
}

// GetADActiveUsers returns all AD users
// using FilterIsPerson and FilterAccountEnabled filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const users = client.GetADActiveUsers();
// log(to_json(users));
// ```
func (c *Client) GetADActiveUsers() SearchResult {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled))
}

// GetAdUserWithNeverExpiringPasswords returns all AD users
// using FilterIsPerson and FilterDontExpirePassword filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const users = client.GetADUserWithNeverExpiringPasswords();
// log(to_json(users));
// ```
func (c *Client) GetADUserWithNeverExpiringPasswords() SearchResult {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterDontExpirePassword))
}

// GetADUserTrustedForDelegation returns all AD users that are trusted for delegation
// using FilterIsPerson and FilterTrustedForDelegation filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const users = client.GetADUserTrustedForDelegation();
// log(to_json(users));
// ```
func (c *Client) GetADUserTrustedForDelegation() SearchResult {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterTrustedForDelegation))
}

// GetADUserWithPasswordNotRequired returns all AD users that do not require a password
// using FilterIsPerson and FilterPasswordNotRequired filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const users = client.GetADUserWithPasswordNotRequired();
// log(to_json(users));
// ```
func (c *Client) GetADUserWithPasswordNotRequired() SearchResult {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterPasswordNotRequired))
}

// GetADGroups returns all AD groups
// using FilterIsGroup filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const groups = client.GetADGroups();
// log(to_json(groups));
// ```
func (c *Client) GetADGroups() SearchResult {
	return c.FindADObjects(FilterIsGroup)
}

// GetADDCList returns all AD domain controllers
// using FilterIsComputer, FilterAccountEnabled and FilterServerTrustAccount filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const dcs = client.GetADDCList();
// log(to_json(dcs));
// ```
func (c *Client) GetADDCList() SearchResult {
	return c.FindADObjects(JoinFilters(FilterIsComputer, FilterAccountEnabled, FilterServerTrustAccount))
}

// GetADAdmins returns all AD admins
// using FilterIsPerson, FilterAccountEnabled and FilterIsAdmin filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const admins = client.GetADAdmins();
// log(to_json(admins));
// ```
func (c *Client) GetADAdmins() SearchResult {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled, FilterIsAdmin))
}

// GetADUserKerberoastable returns all AD users that are kerberoastable
// using FilterIsPerson, FilterAccountEnabled and FilterHasServicePrincipalName filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const kerberoastable = client.GetADUserKerberoastable();
// log(to_json(kerberoastable));
// ```
func (c *Client) GetADUserKerberoastable() SearchResult {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterAccountEnabled, FilterHasServicePrincipalName))
}

// GetADUserAsRepRoastable returns all AD users that are AsRepRoastable
// using FilterIsPerson, and FilterDontRequirePreauth filter query
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const AsRepRoastable = client.GetADUserAsRepRoastable();
// log(to_json(AsRepRoastable));
// ```
func (c *Client) GetADUserAsRepRoastable() SearchResult {
	return c.FindADObjects(JoinFilters(FilterIsPerson, FilterDontRequirePreauth))
}

// GetADDomainSID returns the SID of the AD domain
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const domainSID = client.GetADDomainSID();
// log(domainSID);
// ```
func (c *Client) GetADDomainSID() string {
	r := c.Search(FilterServerTrustAccount, "objectSid")
	c.nj.Require(len(r.Entries) > 0, "no result from GetADDomainSID query")
	for _, entry := range r.Entries {
		if sid, ok := entry.Attributes.Extra["objectSid"]; ok {
			if sid, ok := sid.([]string); ok {
				return DecodeSID(sid[0])
			} else {
				c.nj.HandleError(fmt.Errorf("invalid objectSid type: %T", entry.Attributes.Extra["objectSid"]), "invalid objectSid type")
			}
		}
	}
	c.nj.HandleError(fmt.Errorf("no objectSid found"), "no objectSid found")
	return ""
}
