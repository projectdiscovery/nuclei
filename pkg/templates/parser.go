package templates

import (
	"bufio"
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
	fileutil "github.com/projectdiscovery/utils/file"

	"gopkg.in/yaml.v3"
)

// Global pools for memory reuse - reduces GC pressure and allocation overhead
var (
	// byteBufferPool: Reuses byte buffers for file reading instead of allocating new []byte each time
	byteBufferPool = sync.Pool{
		New: func() any {
			return bytes.NewBuffer(make([]byte, 0, 4096)) // 4KB initial capacity
		},
	}

	// bufReaderPool: Pool a resettable bufio.Reader for streaming decodes
	bufReaderPool = sync.Pool{
		New: func() any {
			return bufio.NewReaderSize(nil, 64<<10) // 64KB;
		},
	}
)

type Parser struct {
	ShouldValidate bool
	NoStrictSyntax bool
	// this cache can be copied safely between ephemeral instances
	parsedTemplatesCache *Cache
	// this cache might potentially contain references to heap objects
	// it's recommended to always empty it at the end of execution
	compiledTemplatesCache *Cache

	// templatePool: Object pool for Template structs to reduce allocation pressure
	templatePool *sync.Pool

	// parsingSemaphore: Limits concurrent parsing to prevent memory exhaustion
	parsingSemaphore chan struct{}

	sync.Mutex
}

func NewParser() *Parser {
	p := &Parser{
		parsedTemplatesCache:   NewCache(),
		compiledTemplatesCache: NewCache(),
		templatePool: &sync.Pool{
			New: func() any {
				return &Template{}
			},
		},
		parsingSemaphore: make(chan struct{}, 10),
	}
	return p
}

func NewParserWithParsedCache(cache *Cache) *Parser {
	return &Parser{
		parsedTemplatesCache:   cache,
		compiledTemplatesCache: NewCache(),
		templatePool: &sync.Pool{
			New: func() interface{} {
				return &Template{}
			},
		},
		parsingSemaphore: make(chan struct{}, 10),
	}
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
		return false, ErrCouldNotLoadTemplate(templatePath, templateParseError.Error())
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
		return false, ErrCouldNotLoadTemplate(templatePath, validationError.Error())
	}

	ret, err := isTemplateInfoMetadataMatch(tagFilter, template, extraTags)
	if err != nil {
		checkOpenFileError(err)
		return ret, ErrCouldNotLoadTemplate(templatePath, err.Error())
	}
	// if template loaded then check the template for optional fields to add warnings
	if ret {
		validationWarning := validateTemplateOptionalFields(template)
		if validationWarning != nil {
			stats.Increment(SyntaxWarningStats)
			checkOpenFileError(validationWarning)
			return ret, ErrCouldNotLoadTemplate(templatePath, validationWarning.Error())
		}
	}
	return ret, nil
}

// getPreprocessedData: Optimized YAML preprocessing with pooled buffers
func (p *Parser) getPreprocessedData(reader io.Reader) ([]byte, error) {
	buf := byteBufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer byteBufferPool.Put(buf)

	_, err := io.Copy(buf, reader)
	if err != nil {
		return nil, err
	}

	// Process the data using existing yamlutil.PreProcess
	return yamlutil.PreProcess(buf.Bytes())
}

// ParseTemplate parses a template and returns a *templates.Template structure
func (p *Parser) ParseTemplate(templatePath string, catalog catalog.Catalog) (any, error) {
	p.parsingSemaphore <- struct{}{}
	defer func() { <-p.parsingSemaphore }()

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

	template := p.templatePool.Get().(*Template)
	defer func() {
		if err != nil {
			*template = Template{}
			p.templatePool.Put(template)
		}
	}()

	var data []byte
	if fileutil.FileExists(templatePath) && config.GetTemplateFormatFromExt(templatePath) == config.YAML {
		data, err = p.getPreprocessedData(reader)
		if err != nil {
			return nil, err
		}
	}

	switch config.GetTemplateFormatFromExt(templatePath) {
	case config.JSON:
		if data == nil {
			buf := byteBufferPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer byteBufferPool.Put(buf)

			if _, err = io.Copy(buf, reader); err != nil {
				return nil, err
			}
			data = buf.Bytes()
		}
		err = json.Unmarshal(data, template)

	case config.YAML:
		if len(data) > 0 {
			err = p.decodeYAMLFromData(data, template)
		} else {
			err = p.decodeYAMLFromReader(reader, template)
		}

	default:
		err = fmt.Errorf("failed to identify template format expected JSON or YAML but got %v", templatePath)
	}

	if err != nil {
		return nil, err
	}

	// Note: We don't return the template to pool here because it's now cached
	p.parsedTemplatesCache.StoreWithoutRaw(templatePath, template, nil)
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

func (p *Parser) decodeYAMLFromData(data []byte, out any) error {
	strict := !p.NoStrictSyntax
	if strict {
		dec := yaml.NewDecoder(bytes.NewReader(data))
		dec.KnownFields(true)
		return dec.Decode(out)
	}
	return yaml.Unmarshal(data, out)
}

func (p *Parser) decodeYAMLFromReader(r io.Reader, out any) error {
	strict := !p.NoStrictSyntax
	br := bufReaderPool.Get().(*bufio.Reader)
	br.Reset(r)
	defer func() {
		br.Reset(nil)
		bufReaderPool.Put(br)
	}()

	dec := yaml.NewDecoder(br)
	if strict {
		dec.KnownFields(true)
	}
	return dec.Decode(out)
}
