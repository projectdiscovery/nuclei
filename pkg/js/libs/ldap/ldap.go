package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/dop251/goja"
	"github.com/go-ldap/ldap/v3"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
)

type (
	// Client is a client for ldap protocol in nuclei
	// @example
	// ```javascript
	// const ldap = require('nuclei/ldap');
	// // here ldap.example.com is the ldap server and acme.com is the realm
	// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
	// ```
	// @example
	// ```javascript
	// const ldap = require('nuclei/ldap');
	// const cfg = new ldap.Config();
	// cfg.Timeout = 10;
	// cfg.ServerName = 'ldap.internal.acme.com';
	// // optional config can be passed as third argument
	// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com', cfg);
	// ```
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
	// @example
	// ```javascript
	// const ldap = require('nuclei/ldap');
	// const cfg = new ldap.Config();
	// cfg.Timeout = 10;
	// cfg.ServerName = 'ldap.internal.acme.com';
	// cfg.Upgrade = true; // upgrade to tls
	// ```
	Config struct {
		// Timeout is the timeout for the ldap client in seconds
		Timeout    int
		ServerName string // default to host (when using tls)
		Upgrade    bool   // when true first connects to non-tls and then upgrades to tls
	}
)

// Constructor for creating a new ldap client
// The following schemas are supported for url: ldap://, ldaps://, ldapi://,
// and cldap:// (RFC1798, deprecated but used by Active Directory).
// ldaps uses TLS/SSL, ldapi uses a Unix domain socket, and cldap uses connectionless LDAP.
// Constructor: constructor(public ldapUrl: string, public realm: string, public config?: Config)
func NewClient(call goja.ConstructorCall, runtime *goja.Runtime) *goja.Object {
	// setup nucleijs utils
	c := &Client{nj: utils.NewNucleiJS(runtime)}
	c.nj.ObjectSig = "Client(ldapUrl,Realm,{Config})" // will be included in error messages

	// get arguments (type assertion is efficient than reflection)
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

	var conn net.Conn
	if u.Scheme == "ldapi" {
		if u.Path == "" || u.Path == "/" {
			u.Path = "/var/run/slapd/ldapi"
		}
		conn, err = protocolstate.Dialer.Dial(context.TODO(), "unix", u.Path)
		c.nj.HandleError(err, "failed to connect to ldap server")
	} else {
		host, port, err := net.SplitHostPort(u.Host)
		if err != nil {
			// we assume that error is due to missing port
			host = u.Host
			port = ""
		}
		if u.Scheme == "" {
			// default to ldap
			u.Scheme = "ldap"
		}

		switch u.Scheme {
		case "cldap":
			if port == "" {
				port = ldap.DefaultLdapPort
			}
			conn, err = protocolstate.Dialer.Dial(context.TODO(), "udp", net.JoinHostPort(host, port))
		case "ldap":
			if port == "" {
				port = ldap.DefaultLdapPort
			}
			conn, err = protocolstate.Dialer.Dial(context.TODO(), "tcp", net.JoinHostPort(host, port))
		case "ldaps":
			if port == "" {
				port = ldap.DefaultLdapsPort
			}
			serverName := host
			if c.cfg.ServerName != "" {
				serverName = c.cfg.ServerName
			}
			conn, err = protocolstate.Dialer.DialTLSWithConfig(context.TODO(), "tcp", net.JoinHostPort(host, port),
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

// Authenticate authenticates with the ldap server using the given username and password
// performs NTLMBind first and then Bind/UnauthenticatedBind if NTLMBind fails
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// client.Authenticate('user', 'password');
// ```
func (c *Client) Authenticate(username, password string) bool {
	c.nj.Require(c.conn != nil, "no existing connection")
	if c.BaseDN == "" {
		c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(c.Realm, "."), ",dc="))
	}
	if err := c.conn.NTLMBind(c.Realm, username, password); err == nil {
		// if bind with NTLMBind(), there is nothing
		// else to do, you are authenticated
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

// AuthenticateWithNTLMHash authenticates with the ldap server using the given username and NTLM hash
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// client.AuthenticateWithNTLMHash('pdtm', 'hash');
// ```
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

// Search accepts whatever filter and returns a list of maps having provided attributes
// as keys and associated values mirroring the ones returned by ldap
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const results = client.Search('(objectClass=*)', 'cn', 'mail');
// ```
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

// AdvancedSearch accepts all values of search request type and return Ldap Entry
// its up to user to handle the response
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const results = client.AdvancedSearch(ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, '(objectClass=*)', ['cn', 'mail'], []);
// ```
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
	// Metadata is the metadata for ldap server.
	// this is returned by CollectMetadata method
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

// CollectLdapMetadata collects metadata from ldap server.
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// const metadata = client.CollectMetadata();
// log(to_json(metadata));
// ```
func (c *Client) CollectMetadata() Metadata {
	c.nj.Require(c.conn != nil, "no existing connection")
	var metadata Metadata
	metadata.Domain = c.Realm
	if c.BaseDN == "" {
		c.BaseDN = fmt.Sprintf("dc=%s", strings.Join(strings.Split(c.Realm, "."), ",dc="))
	}
	metadata.BaseDN = c.BaseDN

	// Use scope as Base since Root DSE doesn't have subentries
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

// close the ldap connection
// @example
// ```javascript
// const ldap = require('nuclei/ldap');
// const client = new ldap.Client('ldap://ldap.example.com', 'acme.com');
// client.Close();
// ```
func (c *Client) Close() {
	c.conn.Close()
}
