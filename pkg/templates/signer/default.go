package signer

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/keys"
	"github.com/projectdiscovery/utils/errkit"
)

// DefaultTemplateVerifiers contains the default template verifiers
var DefaultTemplateVerifiers []*TemplateSigner

func init() {
	h := &KeyHandler{
		UserCert: keys.NucleiCert,
	}
	if err := h.ParseUserCert(); err != nil {
		gologger.Error().Msgf("Could not parse pd nuclei certificate: %s\n", err)
		return
	}
	DefaultTemplateVerifiers = append(DefaultTemplateVerifiers, &TemplateSigner{handler: h})

	// try to load default user cert
	usr := &KeyHandler{}
	if err := usr.ReadCert(CertEnvVarName, config.DefaultConfig.GetKeysDir()); err == nil {
		if err := usr.ParseUserCert(); err != nil {
			gologger.Error().Msgf("malformed user cert found: %s\n", err)
			return
		}
		DefaultTemplateVerifiers = append(DefaultTemplateVerifiers, &TemplateSigner{handler: usr})
	}
}

// AddSignerToDefault adds a signer to the default list of signers
func AddSignerToDefault(s *TemplateSigner) error {
	if s == nil {
		return errkit.New("signer is nil").Build()
	}
	DefaultTemplateVerifiers = append(DefaultTemplateVerifiers, s)
	return nil
}
