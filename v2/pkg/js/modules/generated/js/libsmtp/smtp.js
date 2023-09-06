/**
 * @module smtp
 * This module implements bindings for smtp protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * SMTPClient is a minimal SMTP client for nuclei scripts.
 */
class SMTPClient {
    /**
     * @method
     * IsSMTP checks if a host is running a SMTP server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} IsSMTPResponse - The response indicating if the host is running a SMTP server.
     * @throws {Error} If an error occurs during the check.
     * @example
     * let client = new SMTPClient();
     * let isSMTP = client.IsSMTP("localhost", 25);
     */
    IsSMTP(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    SMTPClient: SMTPClient,
};