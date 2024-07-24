## scrapefuncs

scrapefuncs is go/ast based tool to scrapes all helper functions exposed in javascript with help of go/ast and generates a js file with jsdoc comments using LLM (OpenAI)

### Usage

```console
Usage of ./scrapefuncs:
  -dir string
    	directory to process (default "pkg/js/global")
  -key string
    	openai api key
  -keyfile string
    	openai api key file
  -out string
    	output js file with declarations of all global functions
```


### Example

```console
$ ./scrapefuncs -keyfile ~/.openai.key                                   
[+] Scraped 7 functions

Name: Rand
Signatures: "Rand(n int) []byte"
Description: Rand returns a random byte slice of length n

Name: RandInt
Signatures: "RandInt() int"
Description: RandInt returns a random int

Name: log
Signatures: "log(msg string)"
Signatures: "log(msg map[string]interface{})"
Description: log prints given input to stdout with [JS] prefix for debugging purposes 

Name: getNetworkPort
Signatures: "getNetworkPort(port string, defaultPort string) string"
Description: getNetworkPort registers defaultPort and returns defaultPort if it is a colliding port with other protocols

Name: isPortOpen
Signatures: "isPortOpen(host string, port string, [timeout int]) bool"
Description: isPortOpen checks if given TCP port is open on host. timeout is optional and defaults to 5 seconds

Name: isUDPPortOpen
Signatures: "isUDPPortOpen(host string, port string, [timeout int]) bool"
Description: isUDPPortOpen checks if the given UDP port is open on the host. Timeout is optional and defaults to 5 seconds.

Name: ToBytes
Signatures: "ToBytes(...interface{}) []byte"
Description: ToBytes converts given input to byte slice

Name: ToString
Signatures: "ToString(...interface{}) string"
Description: ToString converts given input to string


[+] Generating jsdoc for all functions

/**
 * Rand returns a random byte slice of length n
 * Rand(n int) []byte
 * @function
 * @param {number} n - The length of the byte slice.
 */
function Rand(n) {
    // implemented in go
};

/**
 * RandInt returns a random int
 * RandInt() int
 * @function
 */
function RandInt() {
    // implemented in go
};

/**
 * log prints given input to stdout with [JS] prefix for debugging purposes
 * log(msg string)
 * log(msg map[string]interface{})
 * @function
 * @param {string|Object} msg - The message to print.
 */
function log(msg) {
    // implemented in go
};

/**
 * getNetworkPort registers defaultPort and returns defaultPort if it is a colliding port with other protocols
 * getNetworkPort(port string, defaultPort string) string
 * @function
 * @param {string} port - The port to check.
 * @param {string} defaultPort - The default port to return if the port is colliding.
 */
function getNetworkPort(port, defaultPort) {
    // implemented in go
};

/**
 * isPortOpen checks if given port is open on host. timeout is optional and defaults to 5 seconds
 * isPortOpen(host string, port string, [timeout int]) bool
 * @function
 * @param {string} host - The host to check.
 * @param {string} port - The port to check.
 * @param {number} [timeout=5] - The timeout in seconds.
 */
function isPortOpen(host, port, timeout = 5) {
    // implemented in go
};

/**
 * ToBytes converts given input to byte slice
 * ToBytes(...interface{}) []byte
 * @function
 * @param {...any} args - The input to convert.
 */
function ToBytes(...args) {
    // implemented in go
};

/**
 * ToString converts given input to string
 * ToString(...interface{}) string
 * @function
 * @param {...any} args - The input to convert.
 */
function ToString(...args) {
    // implemented in go
};
```