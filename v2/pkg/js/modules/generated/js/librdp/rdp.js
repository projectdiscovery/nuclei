/**
 * librdp implements bindings for rdp protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * Client is a client for rdp servers
 */
class Client {
    /**
     * CheckRDPAuth checks if the given host and port are running rdp server
     * with authentication and returns their metadata.
     * @param {string} host - The host of the RDP server.
     * @param {number} port - The port of the RDP server.
     * @returns {Object} CheckRDPAuthResponse - The response from the RDP server.
     * @throws {Error} If there is an error in the RDP server or the connection.
     */
    CheckRDPAuth(host, port) {
        // Implementation here
    };

    /**
     * IsRDP checks if the given host and port are running rdp server.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The Name of the OS is also returned if the connection is successful.
     * @param {string} host - The host of the RDP server.
     * @param {number} port - The port of the RDP server.
     * @returns {Object} IsRDPResponse - The response from the RDP server.
     * @throws {Error} If there is an error in the RDP server or the connection.
     */
    IsRDP(host, port) {
        // Implementation here
    };
};

module.exports = {
    Client: Client,
};