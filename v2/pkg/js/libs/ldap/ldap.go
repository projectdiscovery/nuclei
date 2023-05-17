package ldap

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/praetorian-inc/fingerprintx/pkg/plugins"

	pluginldap "github.com/praetorian-inc/fingerprintx/pkg/plugins/services/ldap"
)

// Client is a client for ldap protocol in golang.
//
// It is a wrapper around the standard library ldap package.
type Client struct{}

// IsLdap checks if the given host and port are running ldap server.
func (c *Client) IsLdap(host string, port int) (bool, error) {
	timeout := 10 * time.Second

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), timeout)
	if err != nil {
		return false, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))

	plugin := &pluginldap.LDAPPlugin{}
	service, err := plugin.Run(conn, timeout, plugins.Target{Host: host})
	if err != nil {
		return false, err
	}
	if service == nil {
		return false, nil
	}
	return true, nil
}

// CollectLdapMetadata collects metadata from ldap server.
func (c *Client) CollectLdapMetadata(domain string, controller string) (map[string]string, error) {
	opts := &ldapSessionOptions{
		domain:           domain,
		domainController: controller,
	}
	conn, err := c.newLdapSession(opts)
	if err != nil {
		return nil, err
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

func (c *Client) newLdapSession(opts *ldapSessionOptions) (*ldap.Conn, error) {
	port := opts.port
	dc := opts.domainController
	if port == 0 {
		port = 389
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", dc, port))
	if err != nil {
		return nil, err
	}

	lConn := ldap.NewConn(conn, false)
	lConn.Start()

	return lConn, nil
}

func (c *Client) close(conn *ldap.Conn) {
	conn.Close()
}

func (c *Client) collectLdapMetadata(lConn *ldap.Conn, opts *ldapSessionOptions) (map[string]string, error) {
	var err error
	if opts.username == "" {
		err = lConn.UnauthenticatedBind("")
	} else {
		err = lConn.Bind(opts.username, opts.password)
	}
	if err != nil {
		return nil, err
	}

	baseDN, _ := getBaseNamingContext(opts, lConn)
	metadata := make(map[string]string)
	metadata["baseDN"] = baseDN
	metadata["domain"] = parseDC(baseDN)

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
		return nil, err
	}
	for _, entry := range resMetadata.Entries {
		for _, attr := range entry.Attributes {
			metadata[attr.Name] = entry.GetAttributeValue(attr.Name)
		}
	}
	return metadata, nil
}

func parseDC(input string) string {
	parts := strings.Split(input, ",")

	for i, part := range parts {
		parts[i] = strings.TrimPrefix(part, "DC=")
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
