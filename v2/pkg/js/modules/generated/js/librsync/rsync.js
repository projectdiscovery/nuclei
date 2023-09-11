/**
 * @module rsync
 */

/**
 * @class
 * @classdesc RsyncClient is a minimal Rsync client for nuclei scripts.
 */
class RsyncClient {
    /**
     * @method
     * @name IsRsync
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {IsRsyncResponse} - The response from the Rsync server.
     * @throws {error} - Throws an error if unable to check.
     * @example
     * let client = new RsyncClient();
     * try {
     *   let response = client.IsRsync("localhost", 22);
     *   console.log(response);
     * } catch (error) {
     *   console.error(error);
     * }
     */
    IsRsync(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    RsyncClient: RsyncClient,
};