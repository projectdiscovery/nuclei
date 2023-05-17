package kerberos

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"strings"

	"github.com/projectdiscovery/gologger"
	kclient "github.com/ropnop/gokrb5/v8/client"
	kconfig "github.com/ropnop/gokrb5/v8/config"
	"github.com/ropnop/gokrb5/v8/iana/errorcode"
	"github.com/ropnop/gokrb5/v8/messages"
)

type Client struct{}

type kerberosEnumUserOpts struct {
	realm  string
	config *kconfig.Config
	kdcs   map[int]string
}

// Taken from kerbrute: https://github.com/ropnop/kerbrute/blob/master/session/session.go

const krb5ConfigTemplateDNS = `[libdefaults]
dns_lookup_kdc = true
default_realm = {{.Realm}}
`

const krb5ConfigTemplateKDC = `[libdefaults]
default_realm = {{.Realm}}
[realms]
{{.Realm}} = {
	kdc = {{.DomainController}}
	admin_server = {{.DomainController}}
}
`

func buildKrb5Template(realm, domainController string) string {
	data := map[string]interface{}{
		"Realm":            realm,
		"DomainController": domainController,
	}
	var kTemplate string
	if domainController == "" {
		kTemplate = krb5ConfigTemplateDNS
	} else {
		kTemplate = krb5ConfigTemplateKDC
	}
	t := template.Must(template.New("krb5ConfigString").Parse(kTemplate))
	builder := &strings.Builder{}
	if err := t.Execute(builder, data); err != nil {
		panic(err)
	}
	return builder.String()
}

func newKerbrosEnumUserOpts(domain, domainController string) (*kerberosEnumUserOpts, error) {
	realm := strings.ToUpper(domain)
	configstring := buildKrb5Template(realm, domainController)
	Config, err := kconfig.NewFromString(configstring)
	if err != nil {
		return nil, err
	}
	_, kdcs, err := Config.GetKDCs(realm, false)
	if err != nil {
		err = fmt.Errorf("couldn't find any KDCs for realm %s. Please specify a Domain Controller", realm)
		return nil, err
	}
	return &kerberosEnumUserOpts{realm: realm, config: Config, kdcs: kdcs}, nil
}

// EnumerateUser returns true if the user exists in the domain
//
// If the user is not found, false is returned.
// If the user is found, true is returned. Optionally, the AS-REP
// hash is also returned if discovered.
func (c *Client) EnumerateUser(domain, controller string, username string) (bool, string, error) {
	opts, err := newKerbrosEnumUserOpts(domain, controller)
	if err != nil {
		return false, "", err
	}
	cl := kclient.NewWithPassword(username, opts.realm, "foobar", opts.config, kclient.DisablePAFXFAST(true))

	req, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return false, "", err
	}
	b, err := req.Marshal()
	if err != nil {
		return false, "", err
	}
	rb, err := cl.SendToKDC(b, opts.realm)
	if err == nil {
		var ASRep messages.ASRep
		err = ASRep.Unmarshal(rb)
		gologger.Info().Msgf("Got happy path err: %v\n", err)
		if err != nil {
			// something went wrong, it's not a valid response
			return false, "", err
		}
		hashcatString, _ := asRepToHashcat(ASRep)
		return true, hashcatString, nil
	}
	e, ok := err.(messages.KRBError)
	if !ok {
		return false, "", err
	}
	switch e.ErrorCode {
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return false, "", nil
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		return true, "", nil
	default:
		return false, "", err

	}
}

func asRepToHashcat(asrep messages.ASRep) (string, error) {
	return fmt.Sprintf("$krb5asrep$%d$%s@%s:%s$%s",
		asrep.EncPart.EType,
		asrep.CName.PrincipalNameString(),
		asrep.CRealm,
		hex.EncodeToString(asrep.EncPart.Cipher[:16]),
		hex.EncodeToString(asrep.EncPart.Cipher[16:])), nil
}
