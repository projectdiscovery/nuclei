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
 * @param {string} defaultPort - The default port to return if the given port is colliding.
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