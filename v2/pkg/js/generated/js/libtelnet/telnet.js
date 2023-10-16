/** @module telnet */

/**
 * @class
 * @classdesc TelnetClient is a minimal Telnet client for nuclei scripts
 */
class TelnetClient {
    /**
    * @method
    * @description IsTelnet checks if a host is running a Telnet server
    * @param {string} host - The host to check for Telnet server.
    * @param {int} port - The port to check for Telnet server.
    * @returns {IsTelnetResponse} - The response of the IsTelnet check.
    * @throws {error} - The error encountered during the IsTelnet check.
    * @example
    * let m = require('nuclei/telnet');
    * let c = m.TelnetClient();
    * let response = c.IsTelnet('localhost', 23);
    */
    IsTelnet(host, port) {
        // implemented in go
    };
};

/**
 * @typedef {object} IsTelnetResponse
 * @description IsTelnetResponse is an object containing the response of the IsTelnet check.
 */
const IsTelnetResponse = {};

module.exports = {
    TelnetClient: TelnetClient,
};