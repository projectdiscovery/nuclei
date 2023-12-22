package kerberos

import (
	"encoding/hex"
	"fmt"
	"html/template"
	"strings"

	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	kclient "github.com/ropnop/gokrb5/v8/client"
	kconfig "github.com/ropnop/gokrb5/v8/config"
	"github.com/ropnop/gokrb5/v8/iana/errorcode"
	"github.com/ropnop/gokrb5/v8/messages"
)

// Client is a kerberos client
type KerberosClient struct{}

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

// EnumerateUserResponse is the response from EnumerateUser
type EnumerateUserResponse struct {
	Valid     bool
	ASREPHash string
}

// EnumerateUser returns true if the user exists in the domain
//
// If the user is not found, false is returned.
// If the user is found, true is returned. Optionally, the AS-REP
// hash is also returned if discovered.
func (c *KerberosClient) EnumerateUser(domain, controller string, username string) (EnumerateUserResponse, error) {

	resp := EnumerateUserResponse{}

	if !protocolstate.IsHostAllowed(domain) {
		// host is not valid according to network policy
		return resp, protocolstate.ErrHostDenied.Msgf(domain)
	}

	opts, err := newKerbrosEnumUserOpts(domain, controller)
	if err != nil {
		return resp, err
	}
	cl := kclient.NewWithPassword(username, opts.realm, "foobar", opts.config, kclient.DisablePAFXFAST(true))
	defer cl.Destroy()

	req, err := messages.NewASReqForTGT(cl.Credentials.Domain(), cl.Config, cl.Credentials.CName())
	if err != nil {
		return resp, err
	}
	b, err := req.Marshal()
	if err != nil {
		return resp, err
	}
	rb, err := cl.SendToKDC(b, opts.realm)
	if err == nil {
		var ASRep messages.ASRep
		err = ASRep.Unmarshal(rb)
		if err != nil {
			// something went wrong, it's not a valid response
			return resp, err
		}
		hashcatString, _ := asRepToHashcat(ASRep)
		resp.Valid = true
		resp.ASREPHash = hashcatString
		return resp, nil
	}
	e, ok := err.(messages.KRBError)
	if !ok {
		return resp, nil
	}
	switch e.ErrorCode {
	case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
		return resp, nil
	case errorcode.KDC_ERR_PREAUTH_REQUIRED:
		resp.Valid = true
		return resp, nil
	default:
		return resp, err

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

type TGS struct {
	Ticket messages.Ticket
	Hash   string
}

func (c *KerberosClient) GetServiceTicket(domain, controller string, username, password string, target, spn string) (TGS, error) {
	var tgs TGS

	if !protocolstate.IsHostAllowed(domain) {
		// host is not valid according to network policy
		return tgs, protocolstate.ErrHostDenied.Msgf(domain)
	}

	opts, err := newKerbrosEnumUserOpts(domain, controller)
	if err != nil {
		return tgs, err
	}
	cl := kclient.NewWithPassword(username, opts.realm, password, opts.config, kclient.DisablePAFXFAST(true))
	defer cl.Destroy()

	ticket, _, err := cl.GetServiceTicket(spn)
	if err != nil {
		return tgs, err
	}

	hashcat, err := tgsToHashcat(ticket, target)
	if err != nil {
		return tgs, err
	}

	return TGS{
		Ticket: ticket,
		Hash:   hashcat,
	}, nil
}

func tgsToHashcat(tgs messages.Ticket, username string) (string, error) {
	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		tgs.EncPart.EType,
		username,
		tgs.Realm,
		strings.Join(tgs.SName.NameString[:], "/"),
		hex.EncodeToString(tgs.EncPart.Cipher[:16]),
		hex.EncodeToString(tgs.EncPart.Cipher[16:]),
	), nil
}
