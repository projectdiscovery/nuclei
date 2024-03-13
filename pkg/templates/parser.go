package templates

import (
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	"gopkg.in/yaml.v2"
)

type Parser struct {
	ShouldValidate         bool
	NoStrictSyntax         bool
	parsedTemplatesCache   *Cache
	compiledTemplatesCache *Cache
}

func New() (*Parser, error) {
	p := &Parser{
		parsedTemplatesCache:   NewCache(),
		compiledTemplatesCache: NewCache(),
	}

	for _, verifier := range signer.DefaultTemplateVerifiers {
		SignatureStats[verifier.Identifier()] = &atomic.Uint64{}
	}
	SignatureStats[Unsigned] = &atomic.Uint64{}

	return p, nil
}

// LoadTemplate returns true if the template is valid and matches the filtering criteria.
func (p *Parser) LoadTemplate(templatePath string, t any, extraTags []string, catalog catalog.Catalog) (bool, error) {
	tagFilter, ok := t.(*TagFilter)
	if !ok {
		panic("not a *TagFilter")
	}
	t, templateParseError := p.ParseTemplate(templatePath, catalog)
	if templateParseError != nil {
		return false, ErrCouldNotLoadTemplate.Msgf(templatePath, templateParseError)
	}
	template, ok := t.(*Template)
	if !ok {
		panic("not a template")
	}

	if len(template.Workflows) > 0 {
		return false, nil
	}

	validationError := validateTemplateMandatoryFields(template)
	if validationError != nil {
		stats.Increment(SyntaxErrorStats)
		return false, ErrCouldNotLoadTemplate.Msgf(templatePath, validationError)
	}

	ret, err := isTemplateInfoMetadataMatch(tagFilter, template, extraTags)
	if err != nil {
		return ret, ErrCouldNotLoadTemplate.Msgf(templatePath, err)
	}
	// if template loaded then check the template for optional fields to add warnings
	if ret {
		validationWarning := validateTemplateOptionalFields(template)
		if validationWarning != nil {
			stats.Increment(SyntaxWarningStats)
			return ret, ErrCouldNotLoadTemplate.Msgf(templatePath, validationWarning)
		}
	}
	return ret, nil
}

// ParseTemplate parses a template and returns a *templates.Template structure
func (p *Parser) ParseTemplate(templatePath string, catalog catalog.Catalog) (any, error) {
	if value, err := p.parsedTemplatesCache.Has(templatePath); value != nil {
		return value, err
	}
	data, err := utils.ReadFromPathOrURL(templatePath, catalog)
	if err != nil {
		return nil, err
	}

	template := &Template{}

	switch config.GetTemplateFormatFromExt(templatePath) {
	case config.JSON:
		err = json.Unmarshal(data, template)
	case config.YAML:
		if p.NoStrictSyntax {
			err = yaml.Unmarshal(data, template)
		} else {
			err = yaml.UnmarshalStrict(data, template)
		}
	default:
		err = fmt.Errorf("failed to identify template format expected JSON or YAML but got %v", templatePath)
	}
	if err != nil {
		return nil, err
	}

	p.parsedTemplatesCache.Store(templatePath, template, nil)
	return template, nil
}

// LoadWorkflow returns true if the workflow is valid and matches the filtering criteria.
func (p *Parser) LoadWorkflow(templatePath string, catalog catalog.Catalog) (bool, error) {
	t, templateParseError := p.ParseTemplate(templatePath, catalog)
	if templateParseError != nil {
		return false, templateParseError
	}

	template, ok := t.(*Template)
	if !ok {
		panic("not a template")
	}

	if len(template.Workflows) > 0 {
		if validationError := validateTemplateMandatoryFields(template); validationError != nil {
			stats.Increment(SyntaxErrorStats)
			return false, validationError
		}
		return true, nil
	}

	return false, nil
}
