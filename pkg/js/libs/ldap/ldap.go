package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/Mzack9999/goja"
	"github.com/go-ldap/ldap/v3"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// Client is a client for ldap protocol in nuclei
	Client struct {
		Host   string // Hostname
		Port   int    // Port
		Realm  string // Realm
		BaseDN string // BaseDN (generated from Realm)

		// unexported
		nj   *utils.NucleiJS // nuclei js utils
		conn *ldap.Conn
		cfg  Config
	}
)

type (
	// Config is extra configuration for the ldap client
	Config struct {
		// Timeout is the timeout for the ldap client in seconds
		Timeout    int
		ServerName string // default to host (when using tls)
		Upgrade    bool   // when true first connects to non-tls and then upgrades to tls
	}
)

// NewClient creates a new ldap client
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	// setup nucleijs utils
	c := &Client{nj: utils.NewNucleiJS(runtime)}
	c.nj.ObjectSig = "Client(ldapUrl,Realm,{Config})" 

	// get arguments
	ldapUrl, _ := c.nj.GetArg(call.Arguments, 0).(string)
	realm, _ := c.nj.GetArg(call.Arguments, 1).(string)
	c.cfg = utils.GetStructTypeSafe[Config](c.nj, call.Arguments, 2, Config{})
	c.Realm = realm
	c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(realm, "."), ",dc="))

	// validate arguments
	c.nj.Require(ldapUrl != "", "ldap url cannot be empty")
	c.nj.Require(realm != "", "realm cannot be empty")

	u, err := url.Parse(ldapUrl)
	c.nj.HandleError(err, "invalid ldap url supported schemas are ldap://, ldaps://, ldapi://, and cldap://")

	executionId := c.nj.ExecutionId()
	dialers := protocolstate.GetDialersWithId(executionId)
	if dialers == nil {
		panic("dialers with executionId " + executionId + " not found")
	}

	// Setup dial context with timeout from config
	dialCtx := context.Background()
	if c.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		dialCtx, cancel = context.WithTimeout(context.Background(), time.Duration(c.cfg.Timeout)*time.Second)
		defer cancel()
	}

	var conn net.Conn
	if u.Scheme == "ldapi" {
		if u.Path == "" || u.Path == "/" {
			u.Path = "/var/run/slapd/ldapi"
		}
		conn, err = dialers.Fastdialer.Dial(dialCtx, "unix", u.Path)
		c.nj.HandleError(err, "failed to connect to ldap server")
	} else {
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			host = u.Host
			port = ""
		}
		if u.Scheme == "" {
			u.Scheme = "ldap"
		}

		switch u.Scheme {
		case "cldap":
			if port == "" {
				port = ldap.DefaultLdapPort
			}
			conn, err = dialers.Fastdialer.Dial(dialCtx, "udp", net.JoinHostPort(host, port))
		case "ldap":
			if port == "" {
				port = ldap.DefaultLdapPort
			}
			conn, err = dialers.Fastdialer.Dial(dialCtx, "tcp", net.JoinHostPort(host, port))
		case "ldaps":
			if port == "" {
				port = ldap.DefaultLdapsPort
			}
			serverName := host
			if c.cfg.ServerName != "" {
				serverName = c.cfg.ServerName
			}
			conn, err = dialers.Fastdialer.DialTLSWithConfig(dialCtx, "tcp", net.JoinHostPort(host, port),
				&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, ServerName: serverName})
		default:
			err = fmt.Errorf("unsupported ldap url schema %v", u.Scheme)
		}
		c.nj.HandleError(err, "failed to connect to ldap server")
	}

	c.conn = ldap.NewConn(conn, u.Scheme == "ldaps")
	if u.Scheme != "ldaps" && c.cfg.Upgrade {
		serverName := u.Hostname()
		if c.cfg.ServerName != "" {
			serverName = c.cfg.ServerName
		}
		if err := c.conn.StartTLS(&tls.Config{InsecureSkipVerify: true, ServerName: serverName}); err != nil {
			c.nj.HandleError(err, "failed to upgrade to tls")
		}
	} else {
		c.conn.Start()
	}

	return utils.LinkConstructor(call, runtime, c)
}

// Authenticate with the ldap server
func (c *Client) Authenticate(username, password string) bool {
	c.nj.Require(c.conn != nil, "no existing connection")
	if c.BaseDN == "" {
		c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(c.Realm, "."), ",dc="))
	}
	if err := c.conn.NTLMBind(c.Realm, username, password); err == nil {
		return true
	}

	var err error
	switch password {
	case "":
		if err = c.conn.UnauthenticatedBind(username); err != nil {
			c.nj.ThrowError(err)
		}
	default:
		if err = c.conn.Bind(username, password); err != nil {
			c.nj.ThrowError(err)
		}
	}
	return err == nil
}

// AuthenticateWithNTLMHash authenticates with NTLM hash
func (c *Client) AuthenticateWithNTLMHash(username, hash string) bool {
	c.nj.Require(c.conn != nil, "no existing connection")
	if c.BaseDN == "" {
		c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(c.Realm, "."), ",dc="))
	}
	var err error
	if err = c.conn.NTLMBindWithHash(c.Realm, username, hash); err != nil {
		c.nj.ThrowError(err)
	}
	return err == nil
}

// Search returns a search result
func (c *Client) Search(filter string, attributes ...string) SearchResult {
	c.nj.Require(c.conn != nil, "no existing connection")
	c.nj.Require(c.BaseDN != "", "base dn cannot be empty")
	c.nj.Require(len(attributes) > 0, "attributes cannot be empty")

	res, err := c.conn.Search(
		ldap.NewSearchRequest(
			"",
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases,
			0, 0, false,
			filter,
			attributes,
			nil,
		),
	)
	c.nj.HandleError(err, "ldap search request failed")
	return *getSearchResult(res)
}

// AdvancedSearch returns a search result
func (c *Client) AdvancedSearch(
	Scope, DerefAliases, SizeLimit, TimeLimit int,
	TypesOnly bool,
	Filter string,
	Attributes []string,
	Controls []ldap.Control) SearchResult {
	c.nj.Require(c.conn != nil, "no existing connection")
	if c.BaseDN == "" {
		c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(c.Realm, "."), ",dc="))
	}
	req := ldap.NewSearchRequest(c.BaseDN, Scope, DerefAliases, SizeLimit, TimeLimit, TypesOnly, Filter, Attributes, Controls)
	res, err := c.conn.Search(req)
	c.nj.HandleError(err, "ldap search request failed")
	c.nj.Require(res != nil, "ldap search request failed got nil response")
	return *getSearchResult(res)
}

type (
	// Metadata is the metadata for ldap server
	Metadata struct {
		BaseDN                        string
		Domain                        string
		DefaultNamingContext          string
		DomainFunctionality           string
		ForestFunctionality           string
		DomainControllerFunctionality string
		DnsHostName                   string
	}
)

// CollectMetadata collects metadata from ldap server
func (c *Client) CollectMetadata() Metadata {
	c.nj.Require(c.conn != nil, "no existing connection")
	var metadata Metadata
	metadata.Domain = c.Realm
	if c.BaseDN == "" {
		c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(c.Realm, "."), ",dc="))
	}
	metadata.BaseDN = c.BaseDN

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
	resMetadata, err := c.conn.Search(srMetadata)
	c.nj.HandleError(err, "ldap search request failed")

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
	return metadata
}

// GetVersion returns the LDAP versions
func (c *Client) GetVersion() []string {
	c.nj.Require(c.conn != nil, "no existing connection")

	sr := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject,
		ldap.NeverDerefAliases,
		0, 0, false,
		"(objectClass=*)",
		[]string{"supportedLDAPVersion"},
		nil)

	res, err := c.conn.Search(sr)
	c.nj.HandleError(err, "failed to get LDAP version")

	if len(res.Entries) > 0 {
		return res.Entries[0].GetAttributeValues("supportedLDAPVersion")
	}

	return []string{"unknown"}
}

// Close the ldap connection
func (c *Client) Close() {
	_ = c.conn.Close()
}
