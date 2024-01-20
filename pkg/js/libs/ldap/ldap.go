package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"

	pluginldap "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ldap"
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
	var con net.Conn
	if ssl {
		con, err = protocolstate.Dialer.DialTLS(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
	} else {
		con, err = protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", host, port))
	}
	if err != nil {
		return false, err
	}

	c.Conn = ldap.NewConn(con, ssl)
	if istls && !ssl {
		// Here if it is not a valid ldap server, the StartTLS will return an error,
		// so, if this check succeeds, there is no need to check if the host is has an LDAP Server:
		// https://github.com/go-ldap/ldap/blob/cdb0754f666833c3e287503ed52d535a41ba10f6/v3/conn.go#L334
		if err := c.Conn.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return false, err
		}
	} else {
		// If the connection is unencrypted or targets LDAPS we check here if the host actually
		// exposes an actual LDAP server
		plugin := &pluginldap.LDAPPlugin{}
		if service, err := plugin.Run(con, 10*time.Second, plugins.Target{Host: host}); err != nil || service == nil {
			return false, err
		}
	}

	c.Host = host
	c.Port = port
	c.TLS = istls
	c.UseSSL = ssl
	return true, nil
}

// CollectLdapMetadata collects metadata from ldap server.
func (c *LdapClient) CollectLdapMetadata(domain string, controller string) (LDAPMetadata, error) {
	opts := &ldapSessionOptions{
		domain:           domain,
		domainController: controller,
	}

	if !protocolstate.IsHostAllowed(controller) {
		// host is not valid according to network policy
		return LDAPMetadata{}, protocolstate.ErrHostDenied.Msgf(controller)
	}

	conn, err := c.newLdapSession(opts)
	if err != nil {
		return LDAPMetadata{}, err
	}
	defer c.close(conn)

	return c.collectLdapMetadata(conn, opts)
}

type ldapSessionOptions struct {
	domain           string
	domainController string
	port             int
	username         string
	password         string
	baseDN           string
}

func (c *LdapClient) newLdapSession(opts *ldapSessionOptions) (*ldap.Conn, error) {
	port := opts.port
	dc := opts.domainController
	if port == 0 {
		port = 389
	}

	conn, err := protocolstate.Dialer.Dial(context.TODO(), "tcp", fmt.Sprintf("%s:%d", dc, port))
	if err != nil {
		return nil, err
	}

	lConn := ldap.NewConn(conn, false)
	lConn.Start()

	return lConn, nil
}

func (c *LdapClient) close(conn *ldap.Conn) {
	conn.Close()
}

// LDAPMetadata is the metadata for ldap server.
type LDAPMetadata struct {
	BaseDN                        string
	Domain                        string
	DefaultNamingContext          string
	DomainFunctionality           string
	ForestFunctionality           string
	DomainControllerFunctionality string
	DnsHostName                   string
}

func (c *LdapClient) collectLdapMetadata(lConn *ldap.Conn, opts *ldapSessionOptions) (LDAPMetadata, error) {
	metadata := LDAPMetadata{}

	var err error
	if opts.username == "" {
		err = lConn.UnauthenticatedBind("")
	} else {
		err = lConn.Bind(opts.username, opts.password)
	}
	if err != nil {
		return metadata, err
	}

	baseDN, _ := getBaseNamingContext(opts, lConn)

	metadata.BaseDN = baseDN
	metadata.Domain = parseDC(baseDN)

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
	resMetadata, err := lConn.Search(srMetadata)
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

func parseDC(input string) string {
	parts := strings.Split(strings.ToLower(input), ",")

	for i, part := range parts {
		parts[i] = strings.TrimPrefix(part, "dc=")
	}

	return strings.Join(parts, ".")
}

func getBaseNamingContext(opts *ldapSessionOptions, conn *ldap.Conn) (string, error) {
	if opts.baseDN != "" {
		return opts.baseDN, nil
	}
	sr := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext"},
		nil)
	res, err := conn.Search(sr)
	if err != nil {
		return "", err
	}
	if len(res.Entries) == 0 {
		return "", fmt.Errorf("error getting metadata: No LDAP responses from server")
	}
	defaultNamingContext := res.Entries[0].GetAttributeValue("defaultNamingContext")
	if defaultNamingContext == "" {
		return "", fmt.Errorf("error getting metadata: attribute defaultNamingContext missing")
	}
	opts.baseDN = defaultNamingContext
	return opts.baseDN, nil
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
	opts := &ldapSessionOptions{
		domain:           domain,
		domainController: controller,
		username:         username,
		password:         password,
	}

	if !protocolstate.IsHostAllowed(controller) {
		// host is not valid according to network policy
		return nil, protocolstate.ErrHostDenied.Msgf(controller)
	}

	conn, err := c.newLdapSession(opts)
	if err != nil {
		return nil, err
	}
	defer c.close(conn)

	domainParts := strings.Split(domain, ".")
	if username == "" {
		err = conn.UnauthenticatedBind("")
	} else {
		err = conn.Bind(
			fmt.Sprintf("%v\\%v", domainParts[0], username),
			password,
		)
	}
	if err != nil {
		return nil, err
	}

	var baseDN strings.Builder
	for i, part := range domainParts {
		baseDN.WriteString("DC=")
		baseDN.WriteString(part)
		if i != len(domainParts)-1 {
			baseDN.WriteString(",")
		}
	}

	sr := ldap.NewSearchRequest(
		baseDN.String(),
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

	res, err := conn.Search(sr)
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
