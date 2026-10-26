package templates

import (
	"bytes"
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
	"github.com/projectdiscovery/utils/errkit"
	fileutil "github.com/projectdiscovery/utils/file"
)

type Parser struct {
	ShouldValidate bool
	NoStrictSyntax bool

	// parsedTemplatesCache stores clean parsed template structures used for
	// validation, filtering, and engine-local compilation. Entries also retain
	// source bytes when they exactly match the parsed structure.
	parsedTemplatesCache *Cache

	// compiledTemplatesCache stores fully compiled templates with all protocol
	// requests.
	// This cache contains references to heap objects and should be purged when
	// no longer needed.
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

// NewExecutionParser creates a parser for one engine execution. Parsed template
// data is shared with the long-lived parent, while compiled templates remain
// private because they retain execution-specific options and mutable state.
func NewExecutionParser(parent *Parser) *Parser {
	if parent == nil {
		return NewParser()
	}

	parent.Lock()
	defer parent.Unlock()

	return &Parser{
		ShouldValidate:         parent.ShouldValidate,
		NoStrictSyntax:         parent.NoStrictSyntax,
		parsedTemplatesCache:   parent.parsedTemplatesCache,
		compiledTemplatesCache: NewCache(),
	}
}

// Purge clears the parsed and compiled template caches. It should be called
// when the parser is no longer needed (e.g. on engine Close) so a long-running
// embedder does not retain every compiled template (a heap-heavy object) for
// the entire process lifetime.
func (p *Parser) Purge() {
	p.Lock()
	defer p.Unlock()
	p.parsedTemplatesCache.Purge()
	p.compiledTemplatesCache.Purge()
}

// PurgeCompiled releases execution-specific compiled templates without
// clearing parsed template data that may be shared by other executions.
func (p *Parser) PurgeCompiled() {
	p.Lock()
	defer p.Unlock()
	p.compiledTemplatesCache.Purge()
}

// Cache returns the parsed templates cache
func (p *Parser) Cache() *Cache {
	return p.parsedTemplatesCache
}

// CompiledCache returns the compiled templates cache
func (p *Parser) CompiledCache() *Cache {
	return p.compiledTemplatesCache
}

func (p *Parser) ParsedCount() int {
	p.Lock()
	defer p.Unlock()
	return len(p.parsedTemplatesCache.items.Map)
}

func (p *Parser) CompiledCount() int {
	p.Lock()
	defer p.Unlock()
	return len(p.compiledTemplatesCache.items.Map)
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
		return false, errkit.Newf("Could not load template %s: %s", templatePath, templateParseError)
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
		stats.Increment(TemplateSyntaxErrorStats)
		return false, errkit.Newf("Could not load template %s: %s", templatePath, validationError)
	}

	ret, err := isTemplateInfoMetadataMatch(tagFilter, template, extraTags)
	if err != nil {
		checkOpenFileError(err)
		return ret, errkit.Newf("Could not load template %s: %s", templatePath, err)
	}
	// if template loaded then check the template for optional fields to add warnings
	if ret {
		validationWarning := validateTemplateOptionalFields(template)
		if validationWarning != nil {
			stats.Increment(TemplateSyntaxWarningStats)
			checkOpenFileError(validationWarning)
			return ret, errkit.Newf("Could not load template %s: %s", templatePath, validationWarning)
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

	// Multiple engine executions can share the parsed cache. Coalesce their
	// concurrent first access so an immutable template is read and parsed once.
	// Recheck inside the flight because another caller may have populated the
	// cache between the optimistic lookup above and becoming the flight leader.
	key := fmt.Sprintf("%t:%s", p.NoStrictSyntax, templatePath)
	loaded, loadErr, _ := p.parsedTemplatesCache.loads.Do(key, func() (any, error) {
		cached, _, cachedErr := p.parsedTemplatesCache.Has(templatePath)
		if cached != nil {
			return cached, cachedErr
		}
		return p.parseTemplate(templatePath, catalog)
	})
	return loaded, loadErr
}

func (p *Parser) parseTemplate(templatePath string, catalog catalog.Catalog) (any, error) {

	reader, err := utils.ReaderFromPathOrURL(templatePath, catalog)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = reader.Close()
	}()

	sourceData, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	data := sourceData
	cacheSource := true

	// For local YAML files, check if preprocessing is needed.
	if fileutil.FileExists(templatePath) && config.GetTemplateFormatFromExt(templatePath) == config.YAML {
		data, err = yamlutil.PreProcess(data, templatePath)
		if err != nil {
			return nil, err
		}

		cacheSource = bytes.Equal(data, sourceData)
	}

	template := &Template{}

	switch config.GetTemplateFormatFromExt(templatePath) {
	case config.JSON:
		if p.NoStrictSyntax {
			err = json.Unmarshal(data, template)
		} else {
			err = template.unmarshalJSONStrict(data)
		}
	case config.YAML:
		if p.NoStrictSyntax {
			err = yamlutil.Unmarshal(data, template)
		} else {
			err = yamlutil.UnmarshalStrict(data, template)
		}
	default:
		err = fmt.Errorf("failed to identify template format expected JSON or YAML but got %v", templatePath)
	}
	if err != nil {
		return nil, err
	}

	if cacheSource {
		p.parsedTemplatesCache.Store(templatePath, template, sourceData, nil)
	} else {
		p.parsedTemplatesCache.StoreWithoutRaw(templatePath, template, nil)
	}

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
			stats.Increment(TemplateSyntaxErrorStats)
			return false, validationError
		}
		return true, nil
	}

	return false, nil
}
