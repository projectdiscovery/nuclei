# Nuclei Architecture Document

A brief overview of Nuclei Engine architecture. This document will be kept updated as the engine progresses.

## pkg/templates

### Template

Template is the basic unit of input to the engine which describes the requests to be made, matching to be done, data to extract, etc.

The template structure is described here. Template level attributes are defined here as well as convenience methods to validate, parse and compile templates creating executers. 

Any attributes etc. required for the template, engine or requests to function are also set here.

Workflows are also compiled, their templates are loaded and compiled as well. Any validations etc. on the paths provided are also done here.

`Parse` function is the main entry point which returns a template for a `filePath` and `executorOptions`. It compiles all the requests for the templates, all the workflows, as well as any self-contained request etc. It also caches the templates in an in-memory cache.

### Preprocessors

Preprocessors are also applied here which can do things at template level. They get data of the template which they can alter at will on runtime. This is used in the engine to do random string generation.

Custom processor can be used if they satisfy the following interface.

```go
type Preprocessor interface {
	Process(data []byte) []byte
}
```

## pkg/model

Model package implements Information structure for Nuclei Templates. `Info` contains all major metadata information for the template. `Classification` structure can also be used to provide additional context to vulnerability data.

It also specifies a `WorkflowLoader` interface that is used during workflow loading in template compilation stage.

```go
type WorkflowLoader interface {
	GetTemplatePathsByTags(tags []string) []string
	GetTemplatePaths(templatesList []string, noValidate bool) []string
}
```

## pkg/protocols

Protocols package implements all the request protocols supported by Nuclei. This includes http, dns, network, headless and file requests as of now. 

### Request

It exposes a `Request` interface that is implemented by all the request protocols supported.

```go
// Request is an interface implemented any protocol based request generator.
type Request interface {
	Compile(options *ExecuterOptions) error
	Requests() int
	GetID() string
	Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)
	Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}
	ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback OutputEventCallback) error
	MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent
	MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent
	GetCompiledOperators() []*operators.Operators
}
```

Many of these methods are similar across protocols while some are very protocol specific. 

A brief overview of the methods is provided below -

- **Compile** - Compiles the request with provided options.
- **Requests** - Returns total requests made.
- **GetID** - Returns any ID for the request
- **Match** - Used to perform matching for patterns using matchers
- **Extract** - Used to perform extraction for patterns using extractors
- **ExecuteWithResults** - Request execution function for input.
- **MakeResultEventItem** - Creates a single result event for the intermediate `InternalWrappedEvent` output structure.
- **MakeResultEvent** - Returns a slice of results based on an `InternalWrappedEvent` internal output event.
- **GetCompiledOperators** - Returns the compiled operators for the request.

`MakeDefaultResultEvent` function can be used as a default for `MakeResultEvent` function when no protocol-specific features need to be implemented for result generation. 

For reference protocol requests implementations, one can look at the below packages  - 

1. [pkg/protocols/http](./pkg/protocols/http)
2. [pkg/protocols/dns](./pkg/protocols/dns)
3. [pkg/protocols/network](./pkg/protocols/network)

### Executer

All these different requests interfaces are converted to an Executer which is also an interface defined in `pkg/protocols` which is used during final execution of the template.

```go
// Executer is an interface implemented any protocol based request executer.
type Executer interface {
	Compile() error
	Requests() int
	Execute(input string) (bool, error)
	ExecuteWithResults(input string, callback OutputEventCallback) error
}
```

The `ExecuteWithResults` function accepts a callback, which gets provided with results during execution in form of `*output.InternalWrappedEvent` structure.

The default executer is provided in `pkg/protocols/common/executer` . It takes a list of Requests and relevant `ExecuterOptions` and implements the Executer interface required for template execution. The executer during Template compilation process is created from this package and used as-is.

A different executer is the Clustered Requests executer which implements the Nuclei Request clustering functionality in `pkg/templates`  We have a single HTTP  request in cases where multiple templates can be clustered and multiple operator lists to match/extract. The first HTTP request is executed while all the template matcher/extractor are evaluated separately.

For Workflow execution, a separate RunWorkflow function is used which executes the workflow independently of the template execution.

With this basic premise set, we can now start exploring the current runner implementation which will also walk us through the architecture of nuclei.

## internal/runner

### Template loading

The first process after all CLI specific initialisation is the loading of template/workflow paths that the user wants to run. This is done by the packages described below.

#### pkg/catalog

This package is used to get paths using mixed syntax. It takes a template directory and performs resolving for template paths both from provided template and current user directory.

The syntax is very versatile and can include filenames, glob patterns, directories, absolute paths, and relative-paths.



Next step is the initialisation of the reporting modules which is handled in `pkg/reporting`.  

#### pkg/reporting

Reporting module contains exporters and trackers as well as a module for deduplication and a module for result formatting. 

Exporters and Trackers are interfaces defined in pkg/reporting.

```go
// Tracker is an interface implemented by an issue tracker
type Tracker interface {
	CreateIssue(event *output.ResultEvent) error
}

// Exporter is an interface implemented by an issue exporter
type Exporter interface {
	Close() error
	Export(event *output.ResultEvent) error
}
```

Exporters include `Elasticsearch`, `markdown`, `sarif` . Trackers include `GitHub` , `GitLab` and `Jira`.

Each exporter and trackers implement their own configuration in YAML format and are very modular in nature, so adding new ones is easy.



After reading all the inputs from various sources and initialisation other miscellaneous options, the next bit is the output writing which is done using `pkg/output` module.

#### pkg/output

Output package implements the output writing functionality for Nuclei.

Output Writer implements the Writer interface which is called each time a result is found for nuclei.

```go
// Writer is an interface which writes output to somewhere for nuclei events.
type Writer interface {
	Close()
	Colorizer() aurora.Aurora
	Write(*ResultEvent) error
	Request(templateID, url, requestType string, err error)
}
```

ResultEvent structure is passed to the Nuclei Output Writer which contains the entire detail of a found result. Various intermediary types like `InternalWrappedEvent` and `InternalEvent` are used throughout nuclei protocols and matchers to describe results in various stages of execution.



 Interactsh is also initialised if it is not explicitly disabled. 

#### pkg/protocols/common/interactsh

Interactsh module is used to provide automatic Out-of-Band vulnerability identification in Nuclei. 

It uses two LRU caches, one for storing interactions for request URLs and one for storing requests for interaction URL. These both caches are used to correlated requests received to the Interactsh OOB server and Nuclei Instance. [Interactsh Client](https://github.com/projectdiscovery/interactsh/pkg/client) package does most of the heavy lifting of this module.

Polling for interactions and server registration only starts when a template uses the interactsh module and is executed by nuclei. After that no registration is required for the entire run.



### RunEnumeration

Next we arrive in the `RunEnumeration` function of the runner.

`HostErrorsCache` is initialised which is used throughout the run of Nuclei enumeration to keep track of errors per host and skip further requests if the errors are greater than the provided threshold. The functionality for the error tracking cache is defined in [hosterrorscache.go](https://github.com/projectdiscovery/nuclei/blob/main/pkg/protocols/common/hosterrorscache/hosterrorscache.go) and is pretty simplistic in nature.

Next the `WorkflowLoader` is initialised which used to load workflows. It exists in `pkg/parsers/workflow_loader.go`

The loader is initialised moving forward which is responsible for Using Catalog, Passed Tags, Filters, Paths, etc. to return compiled `Templates` and `Workflows`. 

#### pkg/catalog/loader

First the input passed by the user as paths is normalised to absolute paths which is done by the `pkg/catalog` module.  Next the path filter module is used to remove the excluded template/workflows paths.

`pkg/parsers` module's `LoadTemplate`,`LoadWorkflow` functions are used to check if the templates pass the validation + are not excluded via tags/severity/etc. filters. If all checks are passed, then the template/workflow is parsed and returned in a compiled form by the `pkg/templates`'s `Parse` function.

`Parse` function performs compilation of all the requests in a template + creates Executers from them returning a runnable Template/Workflow structure.

Clustering module comes in next whose job is to cluster identical HTTP GET requests together (as a lot of the templates perform the same get requests many times, it's a good way to save many requests on large scans with lots of templates). 

### pkg/operators

Operators package implements all the matching and extracting logic of Nuclei. 

```go
// Operators contain the operators that can be applied on protocols
type Operators struct {
	Matchers []*matchers.Matcher
	Extractors []*extractors.Extractor
	MatchersCondition string
}
```

A protocol only needs to embed the `operators.Operators` type shown above, and it can utilise all the matching/extracting functionality of nuclei.

```go
// MatchFunc performs matching operation for a matcher on model and returns true or false.
type MatchFunc func(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string)

// ExtractFunc performs extracting operation for an extractor on model and returns true or false.
type ExtractFunc func(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{}

// Execute executes the operators on data and returns a result structure
func (operators *Operators) Execute(data map[string]interface{}, match MatchFunc, extract ExtractFunc, isDebug bool) (*Result, bool) 
```

The core of this process is the Execute function which takes an input dictionary as well as a Match and Extract function and return a `Result` structure which is used later during nuclei execution to check for results.

```go
// Result is a result structure created from operators running on data.
type Result struct {
	Matched bool
	Extracted bool
	Matches map[string][]string
	Extracts map[string][]string
	OutputExtracts []string
	DynamicValues map[string]interface{}
	PayloadValues map[string]interface{}
}
```

The internal logics for matching and extracting for things like words, regexes, jq, paths, etc. is specified in `pkg/operators/matchers`, `pkg/operators/extractors`. Those packages should be investigated for further look into the topic.


### Template Execution

`pkg/core` provides the engine mechanism which runs the templates/workflows on inputs. It exposes an `Execute` function which does the task of execution while also doing template clustering. The clustering can also be disabled optionally by the user.
 
An example of using the core engine is provided below.

```go
engine := core.New(r.options)
engine.SetExecuterOptions(executerOpts)
results := engine.ExecuteWithOpts(finalTemplates, r.hmapInputProvider, true)
```

### Adding a New Protocol

Protocols form the core of Nuclei Engine. All the request types like `http`, `dns`, etc. are implemented in form of protocol requests.

A protocol must implement the `Protocol` and `Request` interfaces described above in `pkg/protocols`. We'll take the example of an existing protocol implementation - websocket for this short reference around Nuclei internals.

The code for the websocket protocol is contained in `pkg/protocols/others/websocket`. 

Below a high level skeleton of the websocket implementation is provided with all the important parts present.

```go
package websocket

// Request is a request for the Websocket protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-"`

	// description: |
	//   Address contains address for the request
	Address string `yaml:"address,omitempty" jsonschema:"title=address for the websocket request,description=Address contains address for the request"`

    // declarations here
}

// Compile compiles the request generators preparing any requests possible.
func (r *Request) Compile(options *protocols.ExecuterOptions) error {
	r.options = options

    // request compilation here as well as client creation
 
	if len(r.Matchers) > 0 || len(r.Extractors) > 0 {
		compiled := &r.Operators
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		r.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (r *Request) Requests() int {
	if r.generator != nil {
		return r.generator.NewIterator().Total()
	}
	return 1
}

// GetID returns the ID for the request if any.
func (r *Request) GetID() string {
	return ""
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) ExecuteWithResults(input string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
    // payloads init here
	if err := r.executeRequestWithPayloads(input, hostname, value, previous, callback); err != nil {
		return err
	}
	return nil
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (r *Request) executeRequestWithPayloads(input, hostname string, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	header := http.Header{}

    // make the actual request here after setting all options

	event := eventcreator.CreateEventWithAdditionalOptions(r, data, r.options.Options.Debug || r.options.Options.DebugResponse, func(internalWrappedEvent *output.InternalWrappedEvent) {
		internalWrappedEvent.OperatorsResult.PayloadValues = payloadValues
	})
	if r.options.Options.Debug || r.options.Options.DebugResponse {
		responseOutput := responseBuilder.String()
		gologger.Debug().Msgf("[%s] Dumped Websocket response for %s", r.options.TemplateID, input)
		gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, responseOutput, r.options.Options.NoColor))
	}

	callback(event)
	return nil
}

func (r *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(r.options.TemplateID),
		TemplatePath:     types.ToString(r.options.TemplatePath),
		// ... setting more values for result event
	}
	return data
}

// Match performs matching operation for a matcher on model and returns:
// true and a list of matched snippets if the matcher type is supports it
// otherwise false and an empty string slice
func (r *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	return protocols.MakeDefaultMatchFunc(data, matcher)
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (r *Request) Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{} {
	return protocols.MakeDefaultExtractFunc(data, matcher)
}

// MakeResultEvent creates a result event from internal wrapped event
func (r *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(r, wrapped)
}

// GetCompiledOperators returns a list of the compiled operators
func (r *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{r.CompiledOperators}
}

// Type returns the type of the protocol request
func (r *Request) Type() templateTypes.ProtocolType {
	return templateTypes.WebsocketProtocol
}
```

Almost all of these protocols have boilerplate functions for which default implementations have been provided in the `providers` package. Examples are the implementation of `Match`, `Extract`, `MakeResultEvent`, `GetCompiledOperators`, etc. which are almost same throughout Nuclei protocols code. It is enough to copy-paste them unless customization is required.

`eventcreator` package offers `CreateEventWithAdditionalOptions` function which can be used to create result events after doing request execution.

Step by step description of how to add a new protocol to Nuclei - 

1. Add the protocol implementation in `pkg/protocols` directory. If it's a small protocol with fewer options, considering adding it to the `pkg/protocols/others` directory. Add the enum for the new protocol to `pkg/templates/types/types.go`.

2. Add the protocol request structure to the `Template` structure fields. This is done in `pkg/templates/templates.go` with the corresponding import line.

```go

import (
	...
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/others/websocket"
)

// Template is a YAML input file which defines all the requests and
// other metadata for a template.
type Template struct {
	...
	// description: |
	//   Websocket contains the Websocket request to make in the template.
	RequestsWebsocket []*websocket.Request `yaml:"websocket,omitempty" json:"websocket,omitempty" jsonschema:"title=websocket requests to make,description=Websocket requests to make for the template"`
	...
}
```

Also add the protocol case to the `Type` function as well as the `TemplateTypes` array in the same `templates.go` file.

```go
// TemplateTypes is a list of accepted template types
var TemplateTypes = []string{
	...
	"websocket",
}

// Type returns the type of the template
func (t *Template) Type() templateTypes.ProtocolType {
	...
	case len(t.RequestsWebsocket) > 0:
		return templateTypes.WebsocketProtocol
	default:
		return ""
	}
}
```

3. Add the protocol request to the `Requests` function and `compileProtocolRequests` function in the `compile.go` file in same directory.

```go

// Requests return the total request count for the template
func (template *Template) Requests() int {
	return len(template.RequestsDNS) +
		...
		len(template.RequestsSSL) +
		len(template.RequestsWebsocket)
}


// compileProtocolRequests compiles all the protocol requests for the template
func (template *Template) compileProtocolRequests(options protocols.ExecuterOptions) error {
	...

	case len(template.RequestsWebsocket) > 0:
		requests = template.convertRequestToProtocolsRequest(template.RequestsWebsocket)
	}
	template.Executer = executer.NewExecuter(requests, &options)
	return nil
}
```

That's it, you've added a new protocol to Nuclei. The next good step would be to write integration tests which are described in `integration-tests` and `cmd/integration-tests` directories.


## Profiling and Tracing

To analyze Nuclei's performance and resource usage, you can generate CPU & memory profiles and trace files using the `-profile-mem` flag:

```bash
nuclei -t nuclei-templates/ -u https://example.com -profile-mem=nuclei-$(git describe --tags)
```

This command creates three files:

* `nuclei.cpu`: CPU profile
* `nuclei.mem`: Memory (heap) profile
* `nuclei.trace`: Execution trace

### Analyzing the CPU/Memory Profiles

* View the profile in the terminal:

```bash
go tool pprof nuclei.{cpu,mem}
```

* Display overall CPU time for processing $$N$$ targets:

```
go tool pprof -top nuclei.cpu | grep "Total samples"
```

* Display top memory consumers:

```bash
go tool pprof -top nuclei.mem | grep "$(go list -m)" | head -10
```

* Visualize the profile in a web browser:

```bash
go tool pprof -http=:$(shuf -i 1000-99999 -n 1) nuclei.{cpu,mem}
```

### Analyzing the Trace File

To examine the execution trace:

```bash
go tool trace nuclei.trace
```

These tools help identify performance bottlenecks and memory leaks, allowing for targeted optimizations of Nuclei's codebase.

## Project Structure

- [pkg/reporting](./pkg/reporting) - Reporting modules for nuclei.
- [pkg/reporting/exporters/sarif](./pkg/reporting/exporters/sarif) - Sarif Result Exporter
- [pkg/reporting/exporters/markdown](./pkg/reporting/exporters/markdown) - Markdown Result Exporter
- [pkg/reporting/exporters/es](./pkg/reporting/exporters/es) - Elasticsearch Result Exporter
- [pkg/reporting/dedupe](./pkg/reporting/dedupe) - Dedupe module for Results
- [pkg/reporting/trackers/gitlab](./pkg/reporting/trackers/gitlab) - GitLab Issue Tracker Exporter
- [pkg/reporting/trackers/jira](./pkg/reporting/trackers/jira) - Jira Issue Tracker Exporter
- [pkg/reporting/trackers/github](./pkg/reporting/trackers/github) - GitHub Issue Tracker Exporter
- [pkg/reporting/format](./pkg/reporting/format) - Result Formatting Functions
- [pkg/parsers](./pkg/parsers) - Implements template as well as workflow loader for initial template discovery, validation and - loading.
- [pkg/types](./pkg/types) - Contains CLI options as well as misc helper functions.
- [pkg/progress](./pkg/progress) - Progress tracking
- [pkg/operators](./pkg/operators) - Operators for Nuclei
- [pkg/operators/common/dsl](./pkg/operators/common/dsl) - DSL functions for Nuclei YAML Syntax
- [pkg/operators/matchers](./pkg/operators/matchers) - Matchers implementation
- [pkg/operators/extractors](./pkg/operators/extractors) - Extractors implementation
- [pkg/catalog](./pkg/catalog) - Template loading from disk helpers
- [pkg/catalog/config](./pkg/catalog/config) - Internal configuration management
- [pkg/catalog/loader](./pkg/catalog/loader) - Implements loading and validation of templates and workflows.
- [pkg/catalog/loader/filter](./pkg/catalog/loader/filter) - Filter filters templates based on tags and paths
- [pkg/output](./pkg/output) - Output module for nuclei
- [pkg/workflows](./pkg/workflows) - Workflow execution logic + declarations
- [pkg/utils](./pkg/utils) - Utility functions
- [pkg/model](./pkg/model) - Template Info + misc
- [pkg/templates](./pkg/templates) - Templates core starting point
- [pkg/templates/cache](./pkg/templates/cache) - Templates cache
- [pkg/protocols](./pkg/protocols) - Protocol Specification
- [pkg/protocols/file](./pkg/protocols/file) - File protocol
- [pkg/protocols/network](./pkg/protocols/network) - Network protocol
- [pkg/protocols/common/expressions](./pkg/protocols/common/expressions) - Expression evaluation + Templating Support
- [pkg/protocols/common/interactsh](./pkg/protocols/common/interactsh) - Interactsh integration
- [pkg/protocols/common/generators](./pkg/protocols/common/generators) - Payload support for Requests (Sniper, etc.)
- [pkg/protocols/common/executer](./pkg/protocols/common/executer) - Default Template Executer
- [pkg/protocols/common/replacer](./pkg/protocols/common/replacer) - Template replacement helpers
- [pkg/protocols/common/helpers/eventcreator](./pkg/protocols/common/helpers/eventcreator) - Result event creator
- [pkg/protocols/common/helpers/responsehighlighter](./pkg/protocols/common/helpers/responsehighlighter) - Debug response highlighter
- [pkg/protocols/common/helpers/deserialization](./pkg/protocols/common/helpers/deserialization) - Deserialization helper functions
- [pkg/protocols/common/hosterrorscache](./pkg/protocols/common/hosterrorscache) - Host errors cache for tracking erroring hosts
- [pkg/protocols/offlinehttp](./pkg/protocols/offlinehttp) - Offline http protocol
- [pkg/protocols/http](./pkg/protocols/http) - HTTP protocol
- [pkg/protocols/http/race](./pkg/protocols/http/race) - HTTP Race Module
- [pkg/protocols/http/raw](./pkg/protocols/http/raw) - HTTP Raw Request Support
- [pkg/protocols/headless](./pkg/protocols/headless) - Headless Module
- [pkg/protocols/headless/engine](./pkg/protocols/headless/engine) - Internal Headless implementation
- [pkg/protocols/dns](./pkg/protocols/dns) - DNS protocol
- [pkg/projectfile](./pkg/projectfile) - Project File Implementation

### Notes

1. The matching as well as interim output functionality is a bit complex, we should simplify it a bit as well.
