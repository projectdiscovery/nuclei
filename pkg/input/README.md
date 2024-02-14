## input

input package contains and provides loading, parsing , validating and normalizing of input data

### Nested Packages

## [transform](./transform.go)

Transform package transforms or normalizes the input data before it is sent to protocol executer this step mainly involves changes like adding default ports (if missing) , validating if input is file or directory or url and adjusting the input accordingly etc.

## [formats](./formats/README.md)

Formats package contains packages for loading and parsing different input formats like
- [json](./formats/json) - for parsing / loading proxify (Projectdiscovery Format) json input
- [burp](./formats/burp) - for parsing / loading burp suite xml input
- [openapi](./formats/openapi) - for parsing / loading openapi schema input
- [postman](./formats/postman) - for parsing / loading postman collection input
- [swagger](./formats/swagger) - for parsing / loading swagger schema input


## Provider

Provider package contains the interface that every input format should implement for providing that input format to nuclei