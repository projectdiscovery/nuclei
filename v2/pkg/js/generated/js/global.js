/**
 * @function
 * @description Rand returns a random byte slice of length n
 * @param {number} n - The length of the byte slice.
 * @returns {Uint8Array} - The random byte slice.
 * @example
 * let randbytes = Rand(10); // returns a random byte slice of length 10
 */
function Rand(n) {
    // implemented in go
};

/**
 * @function
 * @description RandInt returns a random int
 * @returns {number} - The random integer.
 * @example
 * let myint = m.RandInt(); // returns a random int
 */
function RandInt() {
    // implemented in go
};

/**
 * @function
 * @description log prints given input to stdout with [JS] prefix for debugging purposes
 * @param {string|Object} msg - The message to print.
 * @example
 * log("Hello World!");
 * log({"Hello": "World!"});
 */
function log(msg) {
    // implemented in go
};

/**
 * @function
 * @description getNetworkPort registers defaultPort and returns defaultPort if it is a colliding port with other protocols
 * @param {string} port - The port to check.
 * @param {string} defaultPort - The default port to return if the given port is colliding.
 * @returns {string} - The default port if the given port is colliding, otherwise the given port.
 * @example
 * let port = getNetworkPort(Port, "2843"); // 2843 is default port (even if 80,443 etc is given in Port from input)
 */
function getNetworkPort(port, defaultPort) {
    // implemented in go
};

/**
 * @function
 * @description isPortOpen checks if given port is open on host. timeout is optional and defaults to 5 seconds
 * @param {string} host - The host to check.
 * @param {string} port - The port to check.
 * @param {number} [timeout=5] - The timeout in seconds.
 * @returns {boolean} - True if the port is open, false otherwise.
 * @example
 * let open = isPortOpen("localhost", "80"); // returns true if port 80 is open on localhost
 * let open = isPortOpen("localhost", "80", 10); // returns true if port 80 is open on localhost within 10 seconds
 */
function isPortOpen(host, port, timeout = 5) {
    // implemented in go
};

/**
 * @function
 * @description ToBytes converts given input to byte slice
 * @param {...any} args - The input to convert.
 * @returns {Uint8Array} - The byte slice.
 * @example
 * let mybytes = ToBytes("Hello World!"); // returns byte slice of "Hello World!"
 */
function ToBytes(...args) {
    // implemented in go
};

/**
 * @function
 * @description ToString converts given input to string
 * @param {...any} args - The input to convert.
 * @returns {string} - The string.
 * @example
 * let mystr = ToString([0x48, 0x65, 0x6c, 0x6c, 0x6f]); // returns "Hello"
 */
function ToString(...args) {
    // implemented in go
};
