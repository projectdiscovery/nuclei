package templates

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"

	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// Due to file references in sensitive fields of template
// ex: javascript code in flow or bash command in code.Source etc
// signing / verifying template is only possible after loading the template
// with these fields resolved

var (
	defaultOpts *types.Options = types.DefaultOptions()
	initOnce                   = sync.OnceFunc(func() {
		_ = protocolstate.Init(defaultOpts)
		_ = protocolinit.Init(defaultOpts)
	})
)

// New Signer/Verification logic requires it to load content of file references
// and this is done respecting sandbox restrictions to avoid any security issues
// AllowLocalFileAccess is a function that allows local file access by disabling sandbox restrictions
// and **MUST** be called before signing / verifying any templates for intialization
func TemplateSignerLFA() {
	defaultOpts.AllowLocalFileAccess = true
}

// VerifyTemplateSignature verifies the signature of the template
// using default signers
func VerifyTemplateSignature(templatePath string) (bool, error) {
	template, _, err := getTemplate(templatePath)
	if err != nil {
		return false, err
	}
	return template.Verified, nil
}

// SignTemplate signs the tempalate using custom signer
func SignTemplate(templateSigner *signer.TemplateSigner, templatePath string) error {
	// sign templates requires code files such as javsacript bash command to be included
	// in template hence we first load template and append such resolved file references to content
	initOnce()

	template, bin, err := getTemplate(templatePath)
	if err != nil {
		return errorutil.NewWithErr(err).Msgf("failed to get template from disk")
	}
	if !template.Verified {
		// if template not verified then sign it

		// TODO: only allow re-signer if template is signed by current signer
		// if len(template.RequestsCode) > 0 {
		// 	// verify using current template signer
		// 	// if verified then
		// }

		signatureData, err := templateSigner.Sign(bin, template)
		if err != nil {
			return err
		}
		buff := bytes.NewBuffer(signer.RemoveSignatureFromData(bin))
		buff.WriteString("\n" + signatureData)
		return os.WriteFile(templatePath, buff.Bytes(), 0644)
	}
	return nil
}

func getTemplate(templatePath string) (*Template, []byte, error) {
	catalog := disk.NewCatalog(filepath.Dir(templatePath))
	executerOpts := protocols.ExecutorOptions{
		Catalog:      catalog,
		Options:      defaultOpts,
		TemplatePath: templatePath,
	}
	bin, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, bin, err
	}
	template, err := ParseTemplateFromReader(bytes.NewReader(bin), nil, executerOpts)
	if err != nil {
		return nil, bin, errorutil.NewWithErr(err).Msgf("failed to parse template")
	}
	return template, bin, nil
}
