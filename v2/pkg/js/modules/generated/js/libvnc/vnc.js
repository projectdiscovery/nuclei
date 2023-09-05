/**
 * @module vnc
 * @description vnc implements bindings for vnc protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class Client
 * @description This is a minimal VNC client for nuclei scripts.
 */
class Client {
    /**
     * @method IsVNC
     * @description This method checks if a host is running a VNC server.
     * @param {string} host - The host to check for a VNC server.
     * @param {number} port - The port to check for a VNC server.
     * @returns {boolean} IsVNCResponse - Returns a boolean indicating if the host is running a VNC server and the banner of the VNC server.
     * @throws {Error} If an error occurs during the process.
     * @example
     * let client = new Client();
     * let response = client.IsVNC("localhost", 5900);
     * console.log(response);
     */
    IsVNC(host, port) {
        // Implementation of the method goes here
    };
};


module.exports = {
    Client: Client,
};