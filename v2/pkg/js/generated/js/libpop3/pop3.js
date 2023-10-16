/** @module pop3 */

/**
 * @class
 * @classdesc Pop3Client is a minimal POP3 client for nuclei scripts
 */
class Pop3Client {
    /**
    * @method
    * @description IsPOP3 checks if a host is running a POP3 server
    * @param {string} host - The host to check.
    * @param {number} port - The port to check.
    * @returns {IsPOP3Response} - The response of the check.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/pop3');
    * let c = m.Pop3Client();
    * let response = c.IsPOP3('localhost', 110);
    */
    IsPOP3(host, port) {
        // implemented in go
    };
};

/**
 * @typedef {object} IsPOP3Response
 * @description IsPOP3Response is an object containing the response of the IsPOP3 check.
 */
const IsPOP3Response = {};

module.exports = {
    Pop3Client: Pop3Client,
};