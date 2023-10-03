package signer

import (
	"github.com/projectdiscovery/gologger"
	v2 "github.com/projectdiscovery/nuclei/v2"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// DefaultTemplateVerifiers contains the default template verifiers
var DefaultTemplateVerifiers []*TemplateSigner

func init() {
	h := &KeyHandler{
		UserCert: v2.NucleiCert,
	}
	if err := h.ParseUserCert(); err != nil {
		gologger.Error().Msgf("Could not parse nuclei certificate: %s\n", err)
		return
	}
	DefaultTemplateVerifiers = append(DefaultTemplateVerifiers, &TemplateSigner{handler: h})
}

// AddSignerToDefault adds a signer to the default list of signers
func AddSignerToDefault(s *TemplateSigner) error {
	if s == nil {
		return errorutil.New("signer is nil")
	}
	DefaultTemplateVerifiers = append(DefaultTemplateVerifiers, s)
	return nil
}
