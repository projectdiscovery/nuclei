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
	"github.com/projectdiscovery/utils/errkit"
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

var (
	sharedParsedCacheOnce sync.Once
	sharedParsedCache     *Cache
)

var (
	sharedCompiledCacheOnce sync.Once
	sharedCompiledCache     *Cache
)

// NewParser returns a new parser with a fresh cache
func NewParser() *Parser {
	return &Parser{parsedTemplatesCache: NewCache(), compiledTemplatesCache: NewCache()}
}

// NewParserWithParsedCache returns a parser using provided cache
func NewParserWithParsedCache(cache *Cache) *Parser {
	return &Parser{parsedTemplatesCache: cache, compiledTemplatesCache: NewCache()}
}

// NewSharedParser returns a parser backed by a process-wide shared parsed cache.
// Safe for concurrent use since Cache is concurrency-safe.
func NewSharedParser() *Parser {
	sharedParsedCacheOnce.Do(func() {
		sharedParsedCache = NewCache()
	})
	return &Parser{parsedTemplatesCache: sharedParsedCache, compiledTemplatesCache: NewCache()}
}

// NewSharedParserWithCompiledCache returns a parser backed by process-wide shared
// parsed and compiled caches. Intended for scenarios where compiled executers
// can be safely reused across engines by copying option-bearing fields.
func NewSharedParserWithCompiledCache() *Parser {
	sharedParsedCacheOnce.Do(func() { sharedParsedCache = NewCache() })
	sharedCompiledCacheOnce.Do(func() { sharedCompiledCache = NewCache() })
	return &Parser{parsedTemplatesCache: sharedParsedCache, compiledTemplatesCache: sharedCompiledCache}
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
		stats.Increment(SyntaxErrorStats)
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
			stats.Increment(SyntaxWarningStats)
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

	reader, err := utils.ReaderFromPathOrURL(templatePath, catalog)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = reader.Close()
	}()

	// For local YAML files, check if preprocessing is needed
	var data []byte
	if fileutil.FileExists(templatePath) && config.GetTemplateFormatFromExt(templatePath) == config.YAML {
		data, err = io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		data, err = yamlutil.PreProcess(data)
		if err != nil {
			return nil, err
		}
	}

	template := &Template{}

	switch config.GetTemplateFormatFromExt(templatePath) {
	case config.JSON:
		if data == nil {
			data, err = io.ReadAll(reader)
			if err != nil {
				return nil, err
			}
		}
		err = json.Unmarshal(data, template)
	case config.YAML:
		if data != nil {
			// Already read and preprocessed
			if p.NoStrictSyntax {
				err = yaml.Unmarshal(data, template)
			} else {
				err = yaml.UnmarshalStrict(data, template)
			}
		} else {
			// Stream directly from reader
			decoder := yaml.NewDecoder(reader)
			if !p.NoStrictSyntax {
				decoder.SetStrict(true)
			}
			err = decoder.Decode(template)
		}
	default:
		err = fmt.Errorf("failed to identify template format expected JSON or YAML but got %v", templatePath)
	}
	if err != nil {
		return nil, err
	}

	p.parsedTemplatesCache.Store(templatePath, template, nil, nil) // don't keep raw bytes to save memory
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
