# JS Contribution Guide

The JS layer provides a mechanism to add scriptability into the Nuclei Engine. The `pkg/js` directory contains the implementation of the JS runtime in Nuclei. This document provides a guide to adding new libraries, extending existing ones and other types of contributions.

## First step 

The Very First before making any type of contribution to javascript runtime in nuclei is taking a look at [design.md](./DESIGN.md) to understand spread out design of nuclei javascript runtime.


## Documentation/Typo Contribution

Most of Javascript API Reference documentation is auto-generated with help of code-generation and [jsdocgen](./devtools/jsdocgen/README.md) and hence any type of documentation contribution are always welcome and can be done by editing [javscript jsdoc](./generated/js/) files


## Improving Existing Libraries(aka node_modules)

Improving existing libraries includes adding new functions, types, fixing bugs etc to any of the existing libraries in [libs](./libs/) directory. This is very easy to achieve and can be done by following steps below

1. Do suggested changes in targeted package in [libs](./libs/) directory
2. Refer [devtools](./devtools/README.md) to autogenerate bindings and documentation
3. Check for errors / improve documentation in generated documentation in [generated/js/*](./generated/js/*) directory

## Adding New Libraries(aka node_modules)

Libraries/node_modules represent adding new protocol or something similar and should not include helper functions or types/objects .Adding new libraries requires few more steps than improving existing libraries and can be done by following steps below

1. Refer any existing library in [libs](./libs/) directory to understand style and structure of node_modules
2. Create new package in [libs](./libs/) directory with suggested protocol / library 
3. Refer [devtools](./devtools/README.md) to autogenerate bindings and documentation
4. Check for errors / improve documentation in generated documentation in [generated/js/*](./generated/js/*) directory
5. Import newly created library with '_' import in [compiler](./compiler/compiler.go)


## Adding Helper Objects/Types/Functions

Helper objects/types/functions can simply be understood as javascript utils to simplify writing javscript and reduce code duplication in javascript templates. Helper functions/objects are divided into two categories

### javascript based helpers

javascript based helpers are written in javascript and are available in javascript runtime by default without needing to import any module. These are located in [global/js](./global/js/) directory and are exported using [exports.js](./global/exports.js) file.


### go based helpers

go based helpers are written in go and can import any go library if required. Minimal/Simple helper functions can be directly added using `runtime.Set("function_name", function)` in [global/scripts.go](./global/scripts.go) file. For more complex helpers, a new package can be created in [libs](./libs/) directory and can be imported in [global/scripts.go](./global/scripts.go) file. Refer to existing implementations in [globals](./global/) directory for more details.


### Updating / Publishing Docs

Javscript Protocol Documentation is auto-generated using [jsdoc] and is hosted at [js-proto-docs](https://projectdiscovery.github.io/js-proto-docs/). To update documentation, please follow steps mentioned at [projectdiscovery/js-proto-docs](https://github.com/projectdiscovery/js-proto-docs)


### Go Code Guidelines

1. Always use 'protocolstate.Dialer' (i.e fastdialer) to dial connections instead of net.Dial this has many benefits along with proxy support , **network policy** usage (i.e local network access can be disabled from cli)
2. When usage of 'protocolstate.Dialer' is not possible due to some reason ex: imported library does not accept dialer etc then validate host using 'protocolstate.IsHostAllowed' before dialing connection.
```go
	if !protocolstate.IsHostAllowed(host) {
		// host is not valid according to network policy
		return false, protocolstate.ErrHostDenied.Msgf(host)
	}
```
3. Keep exported package clean. Do not keep unncessary global exports which the consumer of the API doesn't need to know about. Keep only user-exposed API public.
4. Use timeouts and context cancellation when calling Network related stuff. Also make sure to close your connections or provide a mechanism to the user of the API to do so.
5. Always try to return single types from inside javascript with an error like `(IsRDP, error)` instead of returning multiple values `(name, version string, err error)`. The second one will get converted to an array is much harder for consumers to deal with. Instead, try to return `Structures` which will be accessible natively.


### Javascript Code Guidelines

1. Catch exceptions using `try/catch` blocks and handle errors gracefully, showing useful information. By default, the implementation returns a Go error on a unhandled exception along with stack trace in debug mode.
2. Use `let`/`cost` instead of `var` to declare variables.
3. Keep the global scope clean. The VMs are not shared so do not rely on VM state.
4. Use functions to divide the code and keep the implementation clean. 