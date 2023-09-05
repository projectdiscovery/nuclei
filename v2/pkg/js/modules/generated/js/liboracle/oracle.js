/**
 * @fileoverview Implements bindings for oracle protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc A minimal Oracle client for nuclei scripts.
 */
class Client {
    /**
     * @method
     * @name IsOracle
     * @description Checks if a host is running an Oracle server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {IsOracleResponse} The response from the Oracle server.
     * @throws {Error} If an error occurs during the check.
     */
    IsOracle(host, port) {
        // Implementation of the method goes here.
        // If an error occurs, it should be thrown, not returned.
    };
};

module.exports = {
    Client: Client,
};