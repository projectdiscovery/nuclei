/**
 * @module rdp
 */

/**
 * @class
 * RDPClient is a client for rdp servers
 */
class RDPClient {
    /**
     * @method
     * CheckRDPAuth checks if the given host and port are running rdp server
     * with authentication and returns their metadata.
     * @param {string} host - The host of the rdp server
     * @param {number} port - The port of the rdp server
     * @returns {CheckRDPAuthResponse} - The response from the rdp server
     * @throws {error} If the rdp server is not running or there is a problem with the connection
     * @example
     * let client = new RDPClient();
     * let response = client.CheckRDPAuth("localhost", 3389);
     */
    CheckRDPAuth(host, port) {
        // implemented in go
    };

    /**
     * @method
     * IsRDP checks if the given host and port are running rdp server.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The Name of the OS is also returned if the connection is successful.
     * @param {string} host - The host of the rdp server
     * @param {number} port - The port of the rdp server
     * @returns {IsRDPResponse} - The response from the rdp server
     * @throws {error} If the rdp server is not running or there is a problem with the connection
     * @example
     * let client = new RDPClient();
     * let response = client.IsRDP("localhost", 3389);
     */
    IsRDP(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    RDPClient: RDPClient,
};