/** @module smtp */

/**
 * @class
 * @classdesc SMTPClient is a minimal SMTP client for nuclei scripts.
 */
class SMTPClient {
    /**
    * @method
    * @description IsSMTP checks if a host is running a SMTP server.
    * @param {string} host - The host to check.
    * @param {int} port - The port to check.
    * @returns {IsSMTPResponse} - The response of the check.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/smtp');
    * let c = m.SMTPClient();
    * let response = c.IsSMTP('localhost', 25);
    */
    IsSMTP(host, port) {
        // implemented in go
    };
};

/**
 * @typedef {object} IsSMTPResponse
 * @description IsSMTPResponse is an object containing the response of the IsSMTP check.
 */
const IsSMTPResponse = {};

module.exports = {
    SMTPClient: SMTPClient,
};