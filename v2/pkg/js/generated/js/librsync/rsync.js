/** @module rsync */

/**
 * @class
 * @classdesc RsyncClient is a minimal Rsync client for nuclei scripts.
 */
class RsyncClient {
    /**
    * @method
    * @description IsRsync checks if a host is running a Rsync server.
    * @param {string} host - The host to check.
    * @param {int} port - The port to check.
    * @returns {IsRsyncResponse} - The response from the IsRsync check.
    * @throws {error} - The error encountered during the IsRsync check.
    * @example
    * let m = require('nuclei/rsync');
    * let c = m.RsyncClient();
    * let response = c.IsRsync('localhost', 22);
    */
    IsRsync(host, port) {
        // implemented in go
    };
};

/**
 * @typedef {object} IsRsyncResponse
 * @description IsRsyncResponse is an object containing the response from the IsRsync check.
 */
const IsRsyncResponse = {};

module.exports = {
    RsyncClient: RsyncClient,
};