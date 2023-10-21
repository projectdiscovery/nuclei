/**@module rdp */

/**
 * @class
 * @classdesc RDPClient is a client for rdp servers
 */
class RDPClient {
    /**
    * @method
    * @description CheckRDPAuth checks if the given host and port are running rdp server with authentication and returns their metadata.
    * @param {string} host - The host to check.
    * @param {number} port - The port to check.
    * @returns {CheckRDPAuthResponse} - The response from the check.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/rdp');
    * let c = m.RDPClient();
    * let response = c.CheckRDPAuth('localhost', 3389);
    */
    CheckRDPAuth(host, port) {
        // implemented in go
    };

    /**
    * @method
    * @description IsRDP checks if the given host and port are running rdp server. If connection is successful, it returns true. If connection is unsuccessful, it returns false and error. The Name of the OS is also returned if the connection is successful.
    * @param {string} host - The host to check.
    * @param {number} port - The port to check.
    * @returns {IsRDPResponse} - The response from the check.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/rdp');
    * let c = m.RDPClient();
    * let response = c.IsRDP('localhost', 3389);
    */
    IsRDP(host, port) {
        // implemented in go
    };
};

/**
 * @typedef {object} CheckRDPAuthResponse
 * @description CheckRDPAuthResponse is the response from the CheckRDPAuth method.
 */
const CheckRDPAuthResponse = {};

/**
 * @typedef {object} IsRDPResponse
 * @description IsRDPResponse is the response from the IsRDP method.
 */
const IsRDPResponse = {};

module.exports = {
    RDPClient: RDPClient,
};