# formats

Formats implements support for passing a number of request source as input providers to nuclei to be tested for fuzzing related issues.

Currently the following formats are implemented - 

- Burp Suite XML Request/Response file
- Proxify JSONL output file
- OpenAPI Specification file
- Postman Collection file
- Swagger Specification file

Each implementation implements either the entire or a subset of the features of the specifications. These can be increased further to add support as new things or requirements are identified.

Refer to the specific code for each implementation to understand supported features of the specs.


## OpenAPI Specification File

It is designed to generate HTTP requests based on an OpenAPI 3.0 Schema. Here is how these schema components are processed:

### Servers

The module supports multiple server URLs defined in the `Servers` section of the OpenAPI document. It will send requests to all the server URLs defined in the schema.

### Paths and Operations

The module supports all HTTP methods defined under each path in the `Paths` section. For each operation on a path, HTTP requests are generated and sent to the defined server URL. If the operation cannot generate a valid request, a warning will be logged.

### Parameters

The module recognizes parameters defined in the `query`, `header`, `path`, and `cookie` categories. When generating requests, if the `requiredOnly` flag is true, only the required parameters are included. Otherwise, all parameters, regardless of their required status, are used.

The `generateExampleFromSchema` function is used to generate suitable example data for each parameter from their respective schema definitions.

### RequestBody

The module also comprehends request bodies and supports various media types defined in the `Content` field. Currently, the following content-types are supported:

- `application/json`: The module creates application-specific JSON from the defined example schema.

- `application/xml`: The example schema is converted into xml format using `mxj` library.

- `application/x-www-form-urlencoded`: The example schema is converted into URL-encoded form data.

- `multipart/form-data`: The module supports multipart form-data and differentiates between fields and files using the `binary` format under the property schema.

- `text/plain`: Converts the example schema into string format and send as plain text.

For unsupported media types, no appropriate content type is found for the body. After setting up the body of the request, the module dumps the request and sends it to the defined server URL.

### Example Request Generation

This module converts each operation into one or more example HTTP requests. Each request is dumped into a string format, accompanied by its method, URL, headers, and body. These are send as a callback for further processing.

_Please note: This document does not cover other features of OpenAPI specification like responses, security schemes, links, callbacks, etc. as these are not currently handled by the module._

## Postman Collection file

This module parser Postman Collection JSON files.

### 1. Request Parsing:
  Able to parse requests detailed in the Postman package. The parser is capable of interpreting the HTTP method, URL, and Body of each request present in the collection.

### 2. Header Parsing:
  All HTTP headers set in the collection's request are parsed and set in the request.

### 3. Auth Type Parsing:
 Able to parse and set the `Authentication` options provided in the postman collection in the request headers.
  Supported types of authentication:

   1. **API Key**: In header
   2. **Basic**: Setting basic auth through username, password.
   3. **Bearer Token**: Involves setting bearer auth using tokens.
   4. **No Auth**: No authentication is set.

Note: Not all parts of the Postman Collection specification are supported. This parser does not currently support Postman variables or collection level variables and items. It also does not support more authentication types than detailed above.

### Limitations:
* Does not support Postman variables
* Does not support Collection level variables and items
* Limited Authentication types supported

## Swagger Specification file

Swagger specification file is converted from OpenAPI 2.0 format to OpenAPI 3.0 format. After this, the OpenAPI parser from above is used.

## Burp XML / Proxify JSONL

These modules are generic and parse raw requests from these respective tools.
