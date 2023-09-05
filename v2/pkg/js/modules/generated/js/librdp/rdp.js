/**
 * @module rdp
 * @description rdp implements bindings for rdp protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc Client is a client for rdp servers
 */
class Client {
    /**
     * @method
     * @name CheckRDPAuth
     * @description checks if the given host and port are running rdp server with authentication and returns their metadata.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {Object} CheckRDPAuthResponse - The response object.
     * @throws {Error} If the server is not running or authentication fails.
     * @example
     * let client = new Client();
     * let response = client.CheckRDPAuth('localhost', 3389);
     */
    CheckRDPAuth(host, port) {
        // Implementation here
    };

    /**
     * @method
     * @name IsRDP
     * @description checks if the given host and port are running rdp server.
     * If connection is successful, it returns true and the name of the OS.
     * If connection is unsuccessful, it throws an error.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {Object} IsRDPResponse - The response object.
     * @throws {Error} If the server is not running or connection fails.
     * @example
     * let client = new Client();
     * let response = client.IsRDP('localhost', 3389);
     */
    IsRDP(host, port) {
        // Implementation here
    };
};


module.exports = {
    Client: Client,
};