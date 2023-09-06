/** 
 * @module vnc 
 * vnc implements bindings for vnc protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * @class VNCClient
 * @description A minimal VNC client for nuclei scripts.
 */
class VNCClient {
    /**
     * @method IsVNC
     * @description Checks if a host is running a VNC server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {Object} IsVNCResponse - The response object.
     * @throws {error} If an error occurs during the operation.
     * @example
     * let client = new VNCClient();
     * let response = client.IsVNC("localhost", 5900);
     */
    IsVNC(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    VNCClient: VNCClient,
};