package ldap

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type (
	// SearchResult contains search result of any / all ldap search request
	// @example
	// ```javascript
	// const ldap = require('nuclei/ldap');
	// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
	// const results = client.Search('(objectClass=*)', 'cn', 'mail');
	// ```
	SearchResult struct {
		// Referrals contains list of referrals
		Referrals []string `json:"referrals"`
		// Controls contains list of controls
		Controls []string `json:"controls"`
		// Entries contains list of entries
		Entries []LdapEntry `json:"entries"`
	}

	// LdapEntry represents a single LDAP entry
	LdapEntry struct {
		// DN contains distinguished name
		DN string `json:"dn"`
		// Attributes contains list of attributes
		Attributes LdapAttributes `json:"attributes"`
	}

	// LdapAttributes represents all LDAP attributes of a particular
	// ldap entry
	LdapAttributes struct {
		// CurrentTime contains current time
		CurrentTime []string `json:"currentTime,omitempty"`
		// SubschemaSubentry contains subschema subentry
		SubschemaSubentry []string `json:"subschemaSubentry,omitempty"`
		// DsServiceName contains ds service name
		DsServiceName []string `json:"dsServiceName,omitempty"`
		// NamingContexts contains naming contexts
		NamingContexts []string `json:"namingContexts,omitempty"`
		// DefaultNamingContext contains default naming context
		DefaultNamingContext []string `json:"defaultNamingContext,omitempty"`
		// SchemaNamingContext contains schema naming context
		SchemaNamingContext []string `json:"schemaNamingContext,omitempty"`
		// ConfigurationNamingContext contains configuration naming context
		ConfigurationNamingContext []string `json:"configurationNamingContext,omitempty"`
		// RootDomainNamingContext contains root domain naming context
		RootDomainNamingContext []string `json:"rootDomainNamingContext,omitempty"`
		// SupportedLDAPVersion contains supported LDAP version
		SupportedLDAPVersion []string `json:"supportedLDAPVersion,omitempty"`
		// HighestCommittedUSN contains highest committed USN
		HighestCommittedUSN []string `json:"highestCommittedUSN,omitempty"`
		// SupportedSASLMechanisms contains supported SASL mechanisms
		SupportedSASLMechanisms []string `json:"supportedSASLMechanisms,omitempty"`
		// DnsHostName contains DNS host name
		DnsHostName []string `json:"dnsHostName,omitempty"`
		// LdapServiceName contains LDAP service name
		LdapServiceName []string `json:"ldapServiceName,omitempty"`
		// ServerName contains server name
		ServerName []string `json:"serverName,omitempty"`
		// IsSynchronized contains is synchronized
		IsSynchronized []string `json:"isSynchronized,omitempty"`
		// IsGlobalCatalogReady contains is global catalog ready
		IsGlobalCatalogReady []string `json:"isGlobalCatalogReady,omitempty"`
		// DomainFunctionality contains domain functionality
		DomainFunctionality []string `json:"domainFunctionality,omitempty"`
		// ForestFunctionality contains forest functionality
		ForestFunctionality []string `json:"forestFunctionality,omitempty"`
		// DomainControllerFunctionality contains domain controller functionality
		DomainControllerFunctionality []string `json:"domainControllerFunctionality,omitempty"`
		// DistinguishedName contains the distinguished name
		DistinguishedName []string `json:"distinguishedName,omitempty"`
		// SAMAccountName contains the SAM account name
		SAMAccountName []string `json:"sAMAccountName,omitempty"`
		// PWDLastSet contains the password last set time
		PWDLastSet []string `json:"pwdLastSet,omitempty"`
		// LastLogon contains the last logon time
		LastLogon []string `json:"lastLogon,omitempty"`
		// MemberOf contains the groups the entry is a member of
		MemberOf []string `json:"memberOf,omitempty"`
		// ServicePrincipalName contains the service principal names
		ServicePrincipalName []string `json:"servicePrincipalName,omitempty"`
		// Extra contains other extra fields which might be present
		Extra map[string]any `json:"extra,omitempty"`
	}
)

// getSearchResult converts a ldap.SearchResult to a SearchResult
func getSearchResult(sr *ldap.SearchResult) *SearchResult {
	t := &SearchResult{
		Referrals: []string{},
		Controls:  []string{},
		Entries:   []LdapEntry{},
	}
	// add referrals
	t.Referrals = append(t.Referrals, sr.Referrals...)
	// add controls
	for _, ctrl := range sr.Controls {
		t.Controls = append(t.Controls, ctrl.String())
	}
	// add entries
	for _, entry := range sr.Entries {
		t.Entries = append(t.Entries, parseLdapEntry(entry))
	}
	return t
}

func parseLdapEntry(entry *ldap.Entry) LdapEntry {
	e := LdapEntry{
		DN: entry.DN,
	}
	attrs := LdapAttributes{
		Extra: make(map[string]any),
	}
	for _, attr := range entry.Attributes {
		switch attr.Name {
		case "currentTime":
			attrs.CurrentTime = decodeTimestamps(attr.Values)
		case "subschemaSubentry":
			attrs.SubschemaSubentry = attr.Values
		case "dsServiceName":
			attrs.DsServiceName = attr.Values
		case "namingContexts":
			attrs.NamingContexts = attr.Values
		case "defaultNamingContext":
			attrs.DefaultNamingContext = attr.Values
		case "schemaNamingContext":
			attrs.SchemaNamingContext = attr.Values
		case "configurationNamingContext":
			attrs.ConfigurationNamingContext = attr.Values
		case "rootDomainNamingContext":
			attrs.RootDomainNamingContext = attr.Values
		case "supportedLDAPVersion":
			attrs.SupportedLDAPVersion = attr.Values
		case "highestCommittedUSN":
			attrs.HighestCommittedUSN = attr.Values
		case "supportedSASLMechanisms":
			attrs.SupportedSASLMechanisms = attr.Values
		case "dnsHostName":
			attrs.DnsHostName = attr.Values
		case "ldapServiceName":
			attrs.LdapServiceName = attr.Values
		case "serverName":
			attrs.ServerName = attr.Values
		case "isSynchronized":
			attrs.IsSynchronized = attr.Values
		case "isGlobalCatalogReady":
			attrs.IsGlobalCatalogReady = attr.Values
		case "domainFunctionality":
			attrs.DomainFunctionality = attr.Values
		case "forestFunctionality":
			attrs.ForestFunctionality = attr.Values
		case "domainControllerFunctionality":
			attrs.DomainControllerFunctionality = attr.Values
		case "distinguishedName":
			attrs.DistinguishedName = attr.Values
		case "sAMAccountName":
			attrs.SAMAccountName = attr.Values
		case "pwdLastSet":
			attrs.PWDLastSet = decodeTimestamps(attr.Values)
		case "lastLogon":
			attrs.LastLogon = decodeTimestamps(attr.Values)
		case "memberOf":
			attrs.MemberOf = attr.Values
		case "servicePrincipalName":
			attrs.ServicePrincipalName = attr.Values
		default:
			attrs.Extra[attr.Name] = attr.Values
		}
	}
	e.Attributes = attrs
	return e
}

// decodeTimestamps  decodes multiple timestamps
func decodeTimestamps(timestamps []string) []string {
	res := []string{}
	for _, timestamp := range timestamps {
		res = append(res, DecodeADTimestamp(timestamp))
	}
	return res
}

// DecodeSID decodes a SID string
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const sid = ldap.DecodeSID('S-1-5-21-3623811015-3361044348-30300820-1013');
// log(sid);
// ```
func DecodeSID(s string) string {
	b := []byte(s)
	revisionLvl := int(b[0])
	subAuthorityCount := int(b[1]) & 0xFF

	var authority int
	for i := 2; i <= 7; i++ {
		authority = authority | int(b[i])<<(8*(5-(i-2)))
	}

	var size = 4
	var offset = 8
	var subAuthorities []int
	for i := 0; i < subAuthorityCount; i++ {
		var subAuthority int
		for k := 0; k < size; k++ {
			subAuthority = subAuthority | (int(b[offset+k])&0xFF)<<(8*k)
		}
		subAuthorities = append(subAuthorities, subAuthority)
		offset += size
	}

	var builder strings.Builder
	builder.WriteString("S-")
	builder.WriteString(fmt.Sprintf("%d-", revisionLvl))
	builder.WriteString(fmt.Sprintf("%d", authority))
	for _, v := range subAuthorities {
		builder.WriteString(fmt.Sprintf("-%d", v))
	}
	return builder.String()
}

// DecodeADTimestamp decodes an Active Directory timestamp
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const timestamp = ldap.DecodeADTimestamp('132036744000000000');
// log(timestamp);
// ```
func DecodeADTimestamp(timestamp string) string {
	adtime, _ := strconv.ParseInt(timestamp, 10, 64)
	if (adtime == 9223372036854775807) || (adtime == 0) {
		return "Not Set"
	}
	unixtime_int64 := adtime/(10*1000*1000) - 11644473600
	unixtime := time.Unix(unixtime_int64, 0)
	return unixtime.Format("2006-01-02 3:4:5 pm")
}

// DecodeZuluTimestamp decodes a Zulu timestamp
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const timestamp = ldap.DecodeZuluTimestamp('2021-08-25T10:00:00Z');
// log(timestamp);
// ```
func DecodeZuluTimestamp(timestamp string) string {
	zulu, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return ""
	}
	return zulu.Format("2006-01-02 3:4:5 pm")
}
