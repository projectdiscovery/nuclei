/** @module vnc */

/**
 * @class
 * @classdesc VNCClient is a minimal VNC client for nuclei scripts.
 */
class VNCClient {
    /**
    * @method
    * @description IsVNC checks if a host is running a VNC server.
    * @param {string} host - The host to check.
    * @param {number} port - The port to check.
    * @returns {IsVNCResponse} - The response indicating if the host is running a VNC server and the banner of the VNC server.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/vnc');
    * let c = m.VNCClient();
    * let response = c.IsVNC('localhost', 5900);
    */
    IsVNC(host, port) {
        // implemented in go
    };
};

/**
 * @typedef {object} IsVNCResponse
 * @description IsVNCResponse is an object containing the response of the IsVNC method.
 */
const IsVNCResponse = {};

module.exports = {
    VNCClient: VNCClient,
};