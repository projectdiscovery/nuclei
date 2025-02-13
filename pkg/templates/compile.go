package templates

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"sync"
	"sync/atomic"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v3/pkg/js/compiler"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/globalmatchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/offlinehttp"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/signer"
	"github.com/projectdiscovery/nuclei/v3/pkg/tmplexec"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
	errorutil "github.com/projectdiscovery/utils/errors"
	stringsutil "github.com/projectdiscovery/utils/strings"
)

var (
	ErrCreateTemplateExecutor          = errors.New("cannot create template executer")
	ErrIncompatibleWithOfflineMatching = errors.New("template can't be used for offline matching")
	// track how many templates are verfied and by which signer
	SignatureStats = map[string]*atomic.Uint64{}
)

const (
	Unsigned = "unsigned"
)

func init() {
	for _, verifier := range signer.DefaultTemplateVerifiers {
		SignatureStats[verifier.Identifier()] = &atomic.Uint64{}
	}
	SignatureStats[Unsigned] = &atomic.Uint64{}
}

// Parse parses a yaml request template file
// TODO make sure reading from the disk the template parsing happens once: see parsers.ParseTemplate vs templates.Parse
func Parse(filePath string, preprocessor Preprocessor, options protocols.ExecutorOptions) (*Template, error) {
	parser, ok := options.Parser.(*Parser)
	if !ok {
		panic("not a parser")
	}
	if !options.DoNotCache {
		if value, _, err := parser.compiledTemplatesCache.Has(filePath); value != nil {
			return value, err
		}
	}

	var reader io.ReadCloser
	if !options.DoNotCache {
		_, raw, err := parser.parsedTemplatesCache.Has(filePath)
		if err == nil && raw != nil {
			reader = io.NopCloser(bytes.NewReader(raw))
		}
	}
	var err error
	if reader == nil {
		reader, err = utils.ReaderFromPathOrURL(filePath, options.Catalog)
		if err != nil {
			return nil, err
		}
	}

	defer reader.Close()

	options.TemplatePath = filePath
	template, err := ParseTemplateFromReader(reader, preprocessor, options.Copy())
	if err != nil {
		return nil, err
	}
	if template.isGlobalMatchersEnabled() {
		item := &globalmatchers.Item{
			TemplateID:   template.ID,
			TemplatePath: filePath,
			TemplateInfo: template.Info,
		}
		for _, request := range template.RequestsHTTP {
			item.Operators = append(item.Operators, request.CompiledOperators)
		}
		options.GlobalMatchers.AddOperator(item)
		return nil, nil
	}
	// Compile the workflow request
	if len(template.Workflows) > 0 {
		compiled := &template.Workflow

		compileWorkflow(filePath, preprocessor, &options, compiled, options.WorkflowLoader)
		template.CompiledWorkflow = compiled
		template.CompiledWorkflow.Options = &options
	}
	template.Path = filePath
	if !options.DoNotCache {
		parser.compiledTemplatesCache.Store(filePath, template, nil, err)
	}
	return template, nil
}

// isGlobalMatchersEnabled checks if any of requests in the template
// have global matchers enabled. It iterates through all requests and
// returns true if at least one request has global matchers enabled;
// otherwise, it returns false. If global matchers templates are not
// enabled in the options, the method will immediately return false.
//
// Note: This method only checks the `RequestsHTTP`
// field of the template, which is specific to http-protocol-based
// templates.
//
// TODO: support all protocols.
func (template *Template) isGlobalMatchersEnabled() bool {
	if !template.Options.Options.EnableGlobalMatchersTemplates {
		return false
	}

	for _, request := range template.RequestsHTTP {
		if request.GlobalMatchers {
			return true
		}
	}
	return false
}

// parseSelfContainedRequests parses the self contained template requests.
func (template *Template) parseSelfContainedRequests() {
	if template.Signature.Value.String() != "" {
		for _, request := range template.RequestsHTTP {
			request.Signature = template.Signature
		}
	}
	if !template.SelfContained {
		return
	}
	for _, request := range template.RequestsHTTP {
		request.SelfContained = true
	}
	for _, request := range template.RequestsNetwork {
		request.SelfContained = true
	}
	for _, request := range template.RequestsHeadless {
		request.SelfContained = true
	}
}

// Requests returns the total request count for the template
func (template *Template) Requests() int {
	return len(template.RequestsDNS) +
		len(template.RequestsHTTP) +
		len(template.RequestsFile) +
		len(template.RequestsNetwork) +
		len(template.RequestsHeadless) +
		len(template.Workflows) +
		len(template.RequestsSSL) +
		len(template.RequestsWebsocket) +
		len(template.RequestsWHOIS) +
		len(template.RequestsCode) +
		len(template.RequestsJavascript)
}

// compileProtocolRequests compiles all the protocol requests for the template
func (template *Template) compileProtocolRequests(options *protocols.ExecutorOptions) error {
	templateRequests := template.Requests()

	if templateRequests == 0 {
		return fmt.Errorf("no requests defined for %s", template.ID)
	}

	if options.Options.OfflineHTTP {
		return template.compileOfflineHTTPRequest(options)
	}

	var requests []protocols.Request

	if template.hasMultipleRequests() {
		// when multiple requests are present preserve the order of requests and protocols
		// which is already done during unmarshalling
		requests = template.RequestsQueue
		if options.Flow == "" {
			options.IsMultiProtocol = true
		}
	} else {
		if len(template.RequestsDNS) > 0 {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsDNS)...)
		}
		if len(template.RequestsFile) > 0 {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsFile)...)
		}
		if len(template.RequestsNetwork) > 0 {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsNetwork)...)
		}
		if len(template.RequestsHTTP) > 0 {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsHTTP)...)
		}
		if len(template.RequestsHeadless) > 0 && options.Options.Headless {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsHeadless)...)
		}
		if len(template.RequestsSSL) > 0 {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsSSL)...)
		}
		if len(template.RequestsWebsocket) > 0 {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsWebsocket)...)
		}
		if len(template.RequestsWHOIS) > 0 {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsWHOIS)...)
		}
		if len(template.RequestsCode) > 0 && options.Options.EnableCodeTemplates {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsCode)...)
		}
		if len(template.RequestsJavascript) > 0 {
			requests = append(requests, template.convertRequestToProtocolsRequest(template.RequestsJavascript)...)
		}
	}
	var err error
	template.Executer, err = tmplexec.NewTemplateExecuter(requests, options)
	return err
}

// convertRequestToProtocolsRequest is a convenience wrapper to convert
// arbitrary interfaces which are slices of requests from the template to a
// slice of protocols.Request interface items.
func (template *Template) convertRequestToProtocolsRequest(requests interface{}) []protocols.Request {
	switch reflect.TypeOf(requests).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(requests)

		requestSlice := make([]protocols.Request, s.Len())
		for i := 0; i < s.Len(); i++ {
			value := s.Index(i)
			valueInterface := value.Interface()
			requestSlice[i] = valueInterface.(protocols.Request)
		}
		return requestSlice
	}
	return nil
}

// compileOfflineHTTPRequest iterates all requests if offline http mode is
// specified and collects all matchers for all the base request templates
// (those with URL {{BaseURL}} and it's slash variation.)
func (template *Template) compileOfflineHTTPRequest(options *protocols.ExecutorOptions) error {
	operatorsList := []*operators.Operators{}

mainLoop:
	for _, req := range template.RequestsHTTP {
		hasPaths := len(req.Path) > 0
		if !hasPaths {
			break mainLoop
		}
		for _, path := range req.Path {
			pathIsBaseURL := stringsutil.EqualFoldAny(path, "{{BaseURL}}", "{{BaseURL}}/", "/")
			if !pathIsBaseURL {
				break mainLoop
			}
		}
		operatorsList = append(operatorsList, &req.Operators)
	}
	if len(operatorsList) > 0 {
		options.Operators = operatorsList
		var err error
		template.Executer, err = tmplexec.NewTemplateExecuter([]protocols.Request{&offlinehttp.Request{}}, options)
		if err != nil {
			// it seems like flow executor cannot be used for offline http matching (ex:http(1) && http(2))
			return ErrIncompatibleWithOfflineMatching
		}
		return err
	}

	return ErrIncompatibleWithOfflineMatching
}

// ParseTemplateFromReader reads the template from reader
// returns the parsed template
func ParseTemplateFromReader(reader io.Reader, preprocessor Preprocessor, options protocols.ExecutorOptions) (*Template, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	// a preprocessor is a variable like
	// {{randstr}} which is replaced before unmarshalling
	// as it is known to be a random static value per template
	hasPreprocessor := false
	allPreprocessors := getPreprocessors(preprocessor)
	for _, preprocessor := range allPreprocessors {
		if preprocessor.Exists(data) {
			hasPreprocessor = true
			break
		}
	}

	if !hasPreprocessor {
		// if no preprocessors exists parse template and exit
		template, err := parseTemplate(data, options)
		if err != nil {
			return nil, err
		}
		if !template.Verified && len(template.Workflows) == 0 {
			if config.DefaultConfig.LogAllEvents {
				gologger.DefaultLogger.Print().Msgf("[%v] Template %s is not signed or tampered\n", aurora.Yellow("WRN").String(), template.ID)
			}
		}
		return template, nil
	}

	// if preprocessor is required / exists in this template
	// first unmarshal it and check if its verified
	// persist verified status value and then
	// expand all preprocessor and reparse template

	// === signature verification before preprocessors ===
	template, err := parseTemplate(data, options)
	if err != nil {
		return nil, err
	}
	isVerified := template.Verified
	if !template.Verified && len(template.Workflows) == 0 {
		// workflows are not signed by default
		if config.DefaultConfig.LogAllEvents {
			gologger.DefaultLogger.Print().Msgf("[%v] Template %s is not signed or tampered\n", aurora.Yellow("WRN").String(), template.ID)
		}
	}

	generatedConstants := map[string]interface{}{}
	// ==== execute preprocessors ======
	for _, v := range allPreprocessors {
		var replaced map[string]interface{}
		data, replaced = v.ProcessNReturnData(data)
		// preprocess kind of act like a constant and are generated while loading
		// and stay constant for the template lifecycle
		generatedConstants = generators.MergeMaps(generatedConstants, replaced)
	}
	reParsed, err := parseTemplate(data, options)
	if err != nil {
		return nil, err
	}
	// add generated constants to constants map and executer options
	reParsed.Constants = generators.MergeMaps(reParsed.Constants, generatedConstants)
	reParsed.Options.Constants = reParsed.Constants
	reParsed.Verified = isVerified
	return reParsed, nil
}

// this method does not include any kind of preprocessing
func parseTemplate(data []byte, options protocols.ExecutorOptions) (*Template, error) {
	template := &Template{}
	var err error
	switch config.GetTemplateFormatFromExt(template.Path) {
	case config.JSON:
		err = json.Unmarshal(data, template)
	case config.YAML:
		err = yaml.Unmarshal(data, template)
	default:
		// assume its yaml
		if err = yaml.Unmarshal(data, template); err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to parse %s", template.Path)
	}

	if utils.IsBlank(template.Info.Name) {
		return nil, errors.New("no template name field provided")
	}
	if template.Info.Authors.IsEmpty() {
		return nil, errors.New("no template author field provided")
	}

	numberOfWorkflows := len(template.Workflows)
	if numberOfWorkflows > 0 && numberOfWorkflows != template.Requests() {
		return nil, errors.New("workflows cannot have other protocols")
	}

	// use default unknown severity
	if len(template.Workflows) == 0 {
		if template.Info.SeverityHolder.Severity == severity.Undefined {
			// set unknown severity with counter and forced warning
			template.Info.SeverityHolder.Severity = severity.Unknown
			if options.Options.Validate {
				// when validating return error
				return nil, errors.New("no template severity field provided")
			}
		}
	}

	// Setting up variables regarding template metadata
	options.TemplateID = template.ID
	options.TemplateInfo = template.Info
	options.StopAtFirstMatch = template.StopAtFirstMatch

	if template.Variables.Len() > 0 {
		options.Variables = template.Variables
	}

	// if more than 1 request per protocol exist we add request id to protocol request
	// since in template context we have proto_prefix for each protocol it is overwritten
	// if request id is not present
	template.validateAllRequestIDs()

	// create empty context args for template scope
	options.CreateTemplateCtxStore()
	options.ProtocolType = template.Type()
	options.Constants = template.Constants

	// initialize the js compiler if missing
	if options.JsCompiler == nil {
		options.JsCompiler = GetJsCompiler()
	}

	template.Options = &options
	// If no requests, and it is also not a workflow, return error.
	if template.Requests() == 0 {
		return nil, fmt.Errorf("no requests defined for %s", template.ID)
	}

	// load `flow` and `source` in code protocol from file
	// if file is referenced instead of actual source code
	if err := template.ImportFileRefs(template.Options); err != nil {
		return nil, errorutil.NewWithErr(err).Msgf("failed to load file refs for %s", template.ID)
	}

	if err := template.compileProtocolRequests(template.Options); err != nil {
		return nil, err
	}

	if template.Executer != nil {
		if err := template.Executer.Compile(); err != nil {
			return nil, errors.Wrap(err, "could not compile request")
		}
		template.TotalRequests = template.Executer.Requests()
	}
	if template.Executer == nil && template.CompiledWorkflow == nil {
		return nil, ErrCreateTemplateExecutor
	}
	template.parseSelfContainedRequests()

	// check if the template is verified
	// only valid templates can be verified or signed
	var verifier *signer.TemplateSigner
	for _, verifier = range signer.DefaultTemplateVerifiers {
		template.Verified, _ = verifier.Verify(data, template)
		if config.DefaultConfig.LogAllEvents {
			gologger.Verbose().Msgf("template %v verified by %s : %v", template.ID, verifier.Identifier(), template.Verified)
		}
		if template.Verified {
			template.TemplateVerifier = verifier.Identifier()
			break
		}
	}
	options.TemplateVerifier = template.TemplateVerifier
	if !(template.Verified && verifier.Identifier() == "projectdiscovery/nuclei-templates") {
		template.Options.RawTemplate = data
	}
	return template, nil
}

var (
	jsCompiler     *compiler.Compiler
	jsCompilerOnce = sync.OnceFunc(func() {
		jsCompiler = compiler.New()
	})
)

func GetJsCompiler() *compiler.Compiler {
	jsCompilerOnce()
	return jsCompiler
}
