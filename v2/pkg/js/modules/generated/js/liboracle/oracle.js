/** 
 * @module oracle
 * This module implements bindings for oracle protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * OracleClient is a minimal Oracle client for nuclei scripts.
 */
class OracleClient {
    /**
     * @method
     * IsOracle checks if a host is running an Oracle server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {IsOracleResponse} - The response from the Oracle server.
     * @throws {error} If there is an error in the process.
     * @example
     * let oracleClient = new OracleClient();
     * oracleClient.IsOracle("localhost", 1521);
     */
    IsOracle(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    OracleClient: OracleClient,
};