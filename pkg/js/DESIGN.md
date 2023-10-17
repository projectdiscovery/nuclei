# javascript protocol design

javascript protocol is implemented using `goja`(pure go javascript VM) and overall logic/design of its usage is split into multiple packages/directories

## [api_reference](./api_reference/)

api_reference contains a static site generated using `jsdoc` . It contains documentation for all the exposed functions and types in javascript protocol.

## [compiler](./compiler/)

compiler contains abstracted logic for compiling and executing javascript code. It also handles loading javascript aka node modules , adding builtin / global types and functions etc.

## [devtools](./devtools/README.md)

devtools contains development related tools to automate booring tasks like generating bindings, adding jsdoc comments, generating api reference etc.

## [generated](./generated/README.md)

generated contains two types of generated code 

### [- generated/go](./generated/go/)

generated/go contains actual bindings for native go packages using `goja` this involves exposing libraries,functions and types written in go to javascript.

### [- generated/js](./generated/js/)

generated/js contains a visual representation of all exposed functions and types in javascript minus the actual implementation . it is meant to be used as a reference for developers and generating api reference.

## [global](./global/)

global (or builtin) contains all builtin types and functions that are by default available in javascript runtime without needing to import any module using 'require' keyword. Its split into 2 sections

### [- global/js](./global/js/)

global/js contains javascript code and it acts more like a javascript library and contains functions / types written in javascript itself and exported using [exports.js](./global/exports.js)

### [- global/scripts.go](./global/scripts.go)

global/scripts.go contains declaration and implementation of functions written in go and are made available in javascript runtime. It also contains loading javascript based global functions this is done by executing javascript code in every vm instance.

## [gojs](./gojs/)

gojs contain minimalistic types and interfaces used to register packages written in go as node_modules in javascript runtime.

## [libs](./libs/)

libs contains all go native packages that contain **actual** implementation of all the functions and types that are exposed to javascript runtime.