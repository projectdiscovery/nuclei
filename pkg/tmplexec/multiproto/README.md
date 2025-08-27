## multi protocol execution

### Implementation
when template is unmarshalled, if it uses more than one protocol, then order of protocols is preserved and is same is passed to Executor
multiproto is engine/backend for TemplateExecutor which takes care of sharing logic between protocols and executing them in order

### Execution
when multi protocol template is executed , all protocol requests present in Queue are executed in order
and dynamic values extracted are added to template context.

- Protocol Responses
apart from extracted `internal:true` values response fields/values of protocol are added to template context at `ExecutorOptions.TemplateCtx`
which takes care of sync and other issues if any. all response fields are prefixed with template type prefix ex: `ssl_subject_dn`

### Adding New Protocol to multi protocol execution logic
while logic/implementation of multi protocol execution is abstracted. it requires 3 statements to be added in newly implemented protocol
to make response fields of that protocol available to global context

- Add `request.options.GetTemplateCtx(f.input.MetaInput).GetAll()` to variablesMap in `ExecuteWithResults` Method just above `request.options.Variables.Evaluate`
```go
// example
	values := generators.MergeMaps(payloadValues, hostnameVariables, request.options.GetTemplateCtx(f.input.MetaInput).GetAll())
	variablesMap := request.options.Variables.Evaluate(values)
```

- Add all response fields to template context just after response map is available
```go
	outputEvent := request.responseToDSLMap(compiledRequest, response, domain, question, traceData)
	// expose response variables in proto_var format
	// this is no-op if the template is not a multi protocol template
	request.options.AddTemplateVars(request.Type(),request.ID, outputEvent)
```

- Append all available template context values to outputEvent
```go
	// add variables from template context before matching/extraction
	outputEvent = generators.MergeMaps(outputEvent, request.options.GetTemplateCtx(f.input.MetaInput).GetAll())
```

adding these 3 statements takes care of all logic related to multi protocol execution

### Exceptions
- statements 1 & 2 are intentionally skipped in `file` protocol to avoid redundant data
  - file/dir input paths don't contain variables or are used in path (yet) 
  - since files are processed by scanning each line. adding statement 2 will unintenionally load all file(s) data
