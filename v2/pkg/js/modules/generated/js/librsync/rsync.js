/**
 * @module rsync
 * @description This module implements bindings for rsync protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc This class represents a minimal Rsync client for nuclei scripts.
 */
class Client {
    /**
     * @method
     * @name IsRsync
     * @description This method checks if a host is running a Rsync server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check on the host.
     * @returns {boolean} IsRsyncResponse - The response whether the host is running a Rsync server or not.
     * @throws {Error} If an error occurred during the operation.
     * @example
     * let client = new Client();
     * try {
     *     let response = client.IsRsync('localhost', 22);
     *     console.log(response);
     * } catch (error) {
     *     console.error(error);
     * }
     */
    IsRsync(host, port) {
        // remove error return as errors are thrown not returned
        return IsRsyncResponse;
    };
};

/**
 * @description This module exports the Client class.
 */
module.exports = {
    Client: Client,
};