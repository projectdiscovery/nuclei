package utils

import (
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/extensions"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/signer"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

func SignTemplate(sign *signer.Signer, templatePath string) error {
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return err
	}
	signatureData, err := signer.Sign(sign, templateData)
	if err != nil {
		return err
	}
	dataWithoutSignature := signer.RemoveSignatureFromData(templateData)
	return AppendToFile(templatePath, dataWithoutSignature, signatureData)
}

func ProcessFile(sign *signer.Signer, filePath string) error {
	ext := filepath.Ext(filePath)
	if !stringsutil.EqualFoldAny(ext, extensions.YAML) {
		return nil
	}
	err := SignTemplate(sign, filePath)
	if err != nil {
		return errors.Wrapf(err, "could not sign template: %s", filePath)
	}

	ok, err := VerifyTemplateSignature(sign, filePath)
	if err != nil {
		return errors.Wrapf(err, "could not verify template: %s", filePath)
	}
	if !ok {
		return errors.Wrapf(err, "template signature doesn't match: %s", filePath)
	}

	return nil
}

func AppendToFile(path string, data []byte, digest string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.Write(data); err != nil {
		return err
	}

	if _, err := file.WriteString("\n" + digest); err != nil {
		return err
	}
	return nil
}

func VerifyTemplateSignature(sign *signer.Signer, templatePath string) (bool, error) {
	templateData, err := os.ReadFile(templatePath)
	if err != nil {
		return false, err
	}
	return signer.Verify(sign, templateData)
}
