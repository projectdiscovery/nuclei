/**
 * @module telnet
 */

/**
 * @class
 * @classdesc TelnetClient is a minimal Telnet client for nuclei scripts.
 */
class TelnetClient {
    /**
     * @method
     * @name IsTelnet
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} IsTelnetResponse - Returns true if the host is running a Telnet server, false otherwise.
     * @throws {Error} If an error occurred during the operation.
     * @example
     * let client = new TelnetClient();
     * let isTelnet = client.IsTelnet("localhost", 23);
     * if (isTelnet) {
     *   console.log("The host is running a Telnet server.");
     * } else {
     *   console.log("The host is not running a Telnet server.");
     * }
     */
    IsTelnet(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    TelnetClient: TelnetClient,
};