### formats

Formats implements support for passing a number of request source as input providers to nuclei to be tested for fuzzing related issues.

Currently the following formats are implemented - 

- Burp Suite XML Request/Response file
- Proxify JSONL output file
- OpenAPI Specification file
- Postman Collection file
- Swagger Specification file

Each implementation implements either the entire or a subset of the features of the specifications. These can be increased further to add support as new things or requirements are identified.

Refer to the specific code for each implementation to understand supported features of the specs.