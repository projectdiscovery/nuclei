package templates

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/projectdiscovery/nuclei/v3/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/stats"
	yamlutil "github.com/projectdiscovery/nuclei/v3/pkg/utils/yaml"
	fileutil "github.com/projectdiscovery/utils/file"

	"gopkg.in/yaml.v2"
)

type Parser struct {
	ShouldValidate bool
	NoStrictSyntax bool
	// this cache can be copied safely between ephemeral instances
	parsedTemplatesCache *Cache
	// this cache might potentially contain references to heap objects
	// it's recommended to always empty it at the end of execution
	compiledTemplatesCache *Cache
	sync.Mutex
}

func NewParser() *Parser {
	p := &Parser{
		parsedTemplatesCache:   NewCache(),
		compiledTemplatesCache: NewCache(),
	}

	return p
}

func NewParserWithParsedCache(cache *Cache) *Parser {
	return &Parser{
		parsedTemplatesCache:   cache,
		compiledTemplatesCache: NewCache(),
	}
}

// Cache returns the parsed templates cache
func (p *Parser) Cache() *Cache {
	return p.parsedTemplatesCache
}

func checkOpenFileError(err error) bool {
	if err != nil && strings.Contains(err.Error(), "too many open files") {
		panic(err)
	}
	return false
}

// LoadTemplate returns true if the template is valid and matches the filtering criteria.
func (p *Parser) LoadTemplate(templatePath string, t any, extraTags []string, catalog catalog.Catalog) (bool, error) {
	tagFilter, ok := t.(*TagFilter)
	if !ok {
		panic("not a *TagFilter")
	}
	t, templateParseError := p.ParseTemplate(templatePath, catalog)
	if templateParseError != nil {
		checkOpenFileError(templateParseError)
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
		checkOpenFileError(err)
		return ret, ErrCouldNotLoadTemplate.Msgf(templatePath, err)
	}
	// if template loaded then check the template for optional fields to add warnings
	if ret {
		validationWarning := validateTemplateOptionalFields(template)
		if validationWarning != nil {
			stats.Increment(SyntaxWarningStats)
			checkOpenFileError(validationWarning)
			return ret, ErrCouldNotLoadTemplate.Msgf(templatePath, validationWarning)
		}
	}
	return ret, nil
}

// ParseTemplate parses a template and returns a *templates.Template structure
func (p *Parser) ParseTemplate(templatePath string, catalog catalog.Catalog) (any, error) {
	value, _, err := p.parsedTemplatesCache.Has(templatePath)
	if value != nil {
		return value, err
	}

	reader, err := utils.ReaderFromPathOrURL(templatePath, catalog)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = reader.Close()
	}()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// pre-process directives only for local files
	if fileutil.FileExists(templatePath) && config.GetTemplateFormatFromExt(templatePath) == config.YAML {
		data, err = yamlutil.PreProcess(data)
		if err != nil {
			return nil, err
		}
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

	p.parsedTemplatesCache.Store(templatePath, template, data, nil)
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

// CloneForExecutionId creates a clone with updated execution IDs
func (p *Parser) CloneForExecutionId(xid string) *Parser {
	p.Lock()
	defer p.Unlock()

	newParser := &Parser{
		ShouldValidate:         p.ShouldValidate,
		NoStrictSyntax:         p.NoStrictSyntax,
		parsedTemplatesCache:   NewCache(),
		compiledTemplatesCache: NewCache(),
	}

	for k, tpl := range p.parsedTemplatesCache.items.Map {
		newTemplate := templateUpdateExecutionId(tpl.template, xid)
		newParser.parsedTemplatesCache.Store(k, newTemplate, []byte(tpl.raw), tpl.err)
	}

	for k, tpl := range p.compiledTemplatesCache.items.Map {
		newTemplate := templateUpdateExecutionId(tpl.template, xid)
		newParser.compiledTemplatesCache.Store(k, newTemplate, []byte(tpl.raw), tpl.err)
	}

	return newParser
}

func templateUpdateExecutionId(tpl *Template, xid string) *Template {
	// TODO: This is a no-op today since options are patched in elsewhere, but we're keeping this
	// for future work where we may need additional tweaks per template instance.
	return tpl

	/*
		templateBase := *tpl
		var newOpts *protocols.ExecutorOptions
		// Swap out the types.Options execution ID attached to the template
		if templateBase.Options != nil {
			optionsBase := *templateBase.Options //nolint
			templateBase.Options = &optionsBase
			if templateBase.Options.Options != nil {
				optionsOptionsBase := *templateBase.Options.Options //nolint
				templateBase.Options.Options = &optionsOptionsBase
				templateBase.Options.Options.ExecutionId = xid
				newOpts = templateBase.Options
			}
		}
		if newOpts == nil {
			return &templateBase
		}
		for _, r := range templateBase.RequestsDNS {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsHTTP {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsCode {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsFile {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsHeadless {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsNetwork {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsJavascript {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsSSL {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsWHOIS {
			r.UpdateOptions(newOpts)
		}
		for _, r := range templateBase.RequestsWebsocket {
			r.UpdateOptions(newOpts)
		}
		return &templateBase
	*/
}
