# tmplexec

tmplexec also known as template executer executes template it is different from `protocols` package which only contains logic within the scope of one protocol. tmplexec is resposible for executing `Template` with defined logic. with introduction of `multi protocol` and `flow` templates (deprecated package protocols/common/executer) did not seem appropriate/helpful anymore as it is outside of protocol scope and deals with execution of template which can contain 1 requests , or multiple requests of same protocol or multiple requests of different protocols. tmplexec is responsible for executing template and handling all logic related to it.

## Engine/Backends

Currently there are 3 engines for template execution

- `Generic` => executes request[s] of same/one protocol
- `MultiProtocol` => executes requests of multiple protocols with shared logic between protocol requests see [multiprotocol](multiproto/README.md)
- `Flow` => executes requests of one or multiple protocol requests as specified by template in javascript (aka flow) [flow](flow/README.md) 