/** @module oracle */

/**
 * @class
 * @classdesc OracleClient is a minimal Oracle client for nuclei scripts.
 */
class OracleClient {
    /**
    * @method
    * @description IsOracle checks if a host is running an Oracle server.
    * @param {string} host - The host to check.
    * @param {int} port - The port to check.
    * @returns {IsOracleResponse} - The response from the Oracle server.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/oracle');
    * let c = m.OracleClient();
    * let response = c.IsOracle('localhost', 1521);
    */
    IsOracle(host, port) {
        // implemented in go
    };
};

/**
 * @typedef {object} IsOracleResponse
 * @description IsOracleResponse is an object containing the response from the Oracle server.
 */
const IsOracleResponse = {};

module.exports = {
    OracleClient: OracleClient,
};