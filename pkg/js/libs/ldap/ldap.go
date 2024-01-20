package ldap

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

// Client is a client for ldap protocol in golang.
//
// It is a wrapper around the standard library ldap package.
type LdapClient struct {
	BaseDN string
	Realm  string
	Host   string
	Conn   *ldap.Conn
	Port   int
	UseSSL bool
	TLS    bool
}

// Connect is a method for LdapClient that stores information about of the ldap
// connection, tests it and verifies that the server is a valid ldap server
//
// returns the success status
func (c *LdapClient) Connect(host string, port int, ssl, istls bool) (bool, error) {
	if c.Conn != nil {
		return true, nil
	}

	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}

	var err error
	if ssl {
		config := &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		}
		c.Conn, err = ldap.DialTLS("tcp", fmt.Sprintf("%s:%d", host, port), config)
	} else {
		c.Conn, err = ldap.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	}
	if err != nil {
		return false, err
	}

	if istls && !ssl {
		// Here if it is not a valid ldap server, the StartTLS will return an error,
		// so, if this check succeeds, there is no need to check if the host is has an LDAP Server:
		// https://github.com/go-ldap/ldap/blob/cdb0754f666833c3e287503ed52d535a41ba10f6/v3/conn.go#L334
		if err := c.Conn.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return false, err
		}
	}

	c.Host = host
	c.Port = port
	c.TLS = istls
	c.UseSSL = ssl
	return true, nil
}

func (c *LdapClient) Authenticate(realm string, username, password string) (bool, error) {
	if c.Conn == nil {
		return false, fmt.Errorf("no existing connection")
	}

	c.Realm = realm
	c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(realm, "."), ",dc="))

	if err := c.Conn.NTLMBind(realm, username, password); err == nil {
		// if bind with NTLMBind(), there is nothing
		// else to do, you are authenticated
		return true, nil
	}

	switch password {
	case "":
		if err := c.Conn.UnauthenticatedBind(username); err != nil {
			return false, err
		}
	default:
		if err := c.Conn.Bind(username, password); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (c *LdapClient) AuthenticateWithNTLMHash(realm string, username, hash string) (bool, error) {
	if c.Conn == nil {
		return false, fmt.Errorf("no existing connection")
	}
	c.Realm = realm
	c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(realm, "."), ",dc="))
	if err := c.Conn.NTLMBindWithHash(realm, username, hash); err != nil {
		return false, err
	}
	return true, nil
}

// Search is a method that uses the already Connect()'ed client to query the LDAP
// server, works for openldap and for Microsoft's Active Directory Ldap
//
// accepts whatever filter and returns a list of maps having provided attributes
// as keys and associated values mirroring the ones returned by ldap
func (c *LdapClient) Search(filter string, attributes ...string) ([]map[string][]string, error) {
	res, err := c.Conn.Search(ldap.NewSearchRequest(
		c.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false, filter, attributes, nil,
	))
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no result found in search")
	}

	var out []map[string][]string
	for _, r := range res.Entries {
		app := make(map[string][]string)
		empty := true
		for _, a := range attributes {
			v := r.GetAttributeValues(a)
			if len(v) > 0 {
				app[a] = v
				empty = false
			}
		}
		if !empty {
			out = append(out, app)
		}
	}
	return out, nil
}

// Metadata is the metadata for ldap server.
type Metadata struct {
	BaseDN                        string
	Domain                        string
	DefaultNamingContext          string
	DomainFunctionality           string
	ForestFunctionality           string
	DomainControllerFunctionality string
	DnsHostName                   string
}

// CollectLdapMetadata collects metadata from ldap server.
func (c *LdapClient) CollectMetadata(domain string, controller string) (Metadata, error) {
	if c.Conn == nil {
		return Metadata{}, fmt.Errorf("no existing connection")
	}
	defer c.Conn.Close()

	var metadata Metadata

	metadata.BaseDN = c.BaseDN
	metadata.Domain = c.Realm

	srMetadata := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{
			"defaultNamingContext",
			"domainFunctionality",
			"forestFunctionality",
			"domainControllerFunctionality",
			"dnsHostName",
		},
		nil)
	resMetadata, err := c.Conn.Search(srMetadata)
	if err != nil {
		return metadata, err
	}
	for _, entry := range resMetadata.Entries {
		for _, attr := range entry.Attributes {
			value := entry.GetAttributeValue(attr.Name)
			switch attr.Name {
			case "defaultNamingContext":
				metadata.DefaultNamingContext = value
			case "domainFunctionality":
				metadata.DomainFunctionality = value
			case "forestFunctionality":
				metadata.ForestFunctionality = value
			case "domainControllerFunctionality":
				metadata.DomainControllerFunctionality = value
			case "dnsHostName":
				metadata.DnsHostName = value
			}
		}
	}
	return metadata, nil
}

// KerberoastableUser contains the important fields of the Active Directory
// kerberoastable user
type KerberoastableUser struct {
	SAMAccountName       string
	ServicePrincipalName string
	PWDLastSet           string
	MemberOf             string
	UserAccountControl   string
	LastLogon            string
}

// GetKerberoastableUsers collects all "person" users that have an SPN
// associated with them. The LDAP filter is built with the same logic as
// "GetUserSPNs.py", the well-known impacket example by Forta.
// https://github.com/fortra/impacket/blob/master/examples/GetUserSPNs.py#L297
//
// Returns a list of KerberoastableUser, if an error occurs, returns an empty
// slice and the raised error
func (c *LdapClient) GetKerberoastableUsers(domain, controller string, username, password string) ([]KerberoastableUser, error) {
	sr := ldap.NewSearchRequest(
		c.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0, 0, false,
		// (&(is_user)         (!(account_is_disabled))                         (has_SPN))
		"(&(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2))(servicePrincipalName=*))",
		[]string{
			"SAMAccountName",
			"ServicePrincipalName",
			"pwdLastSet",
			"MemberOf",
			"userAccountControl",
			"lastLogon",
		},
		nil,
	)

	res, err := c.Conn.Search(sr)
	if err != nil {
		return nil, err
	}

	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("no kerberoastable user found")
	}

	var ku []KerberoastableUser
	for _, usr := range res.Entries {
		ku = append(ku, KerberoastableUser{
			SAMAccountName:       usr.GetAttributeValue("sAMAccountName"),
			ServicePrincipalName: usr.GetAttributeValue("servicePrincipalName"),
			PWDLastSet:           usr.GetAttributeValue("pwdLastSet"),
			MemberOf:             usr.GetAttributeValue("MemberOf"),
			UserAccountControl:   usr.GetAttributeValue("userAccountControl"),
			LastLogon:            usr.GetAttributeValue("lastLogon"),
		})
	}
	return ku, nil
}
