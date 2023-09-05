/**
 * @fileoverview Implements bindings for rsync protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class Client
 * @classdesc A minimal Rsync client for nuclei scripts.
 */
class Client {
    /**
     * @method IsRsync
     * @description Checks if a host is running a Rsync server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {IsRsyncResponse} The response from the Rsync server.
     * @throws {Error} If an error occurs during the check.
     */
    IsRsync(host, port) {
        // Implementation of the method goes here.
        // If an error occurs, it should be thrown, not returned.
    };
};

module.exports = {
    Client: Client,
};