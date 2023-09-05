/**
 * @fileoverview Implements bindings for VNC protocol in JavaScript to be used from nuclei scanner.
 */

/**
 * @class
 * @description A minimal VNC client for nuclei scripts.
 */
class Client {
    /**
     * @method
     * @description Checks if a host is running a VNC server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {Object} IsVNCResponse - An object containing a boolean indicating if the host is running a VNC server and the banner of the VNC server.
     * @throws {Error} If an error occurs during the operation.
     */
    IsVNC(host, port) {
        // Implementation of the method goes here.
        // If an error occurs, it should be thrown, not returned.
    };
};

module.exports = {
    Client: Client,
};