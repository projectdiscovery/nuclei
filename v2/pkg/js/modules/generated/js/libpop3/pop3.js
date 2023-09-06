/** 
 * @module pop3 
 * This module implements bindings for pop3 protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc Pop3Client is a minimal POP3 client for nuclei scripts.
 */
class Pop3Client {
    /**
     * @method
     * @name IsPOP3
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} IsPOP3Response - Returns true if the host is running a POP3 server, false otherwise.
     * @throws {Error} If an error occurs during the check.
     * @example
     * let client = new Pop3Client();
     * let isPop3 = client.IsPOP3('localhost', 110);
     */
    IsPOP3(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    Pop3Client: Pop3Client,
};