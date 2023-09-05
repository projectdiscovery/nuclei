/**
 * libpop3 implements bindings for pop3 protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * Client is a minimal POP3 client for nuclei scripts.
 * @class
 */
class Client {
    /**
     * IsPOP3 checks if a host is running a POP3 server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} IsPOP3Response - The response indicating if the host is running a POP3 server.
     * @throws {Error} If an error occurs during the check.
     */
    IsPOP3(host, port) {
        // Removed 'error' as errors are thrown not returned in JavaScript
        return IsPOP3Response;
    };
};

module.exports = {
    /** 
     * @type {Client} 
     */
    Client: Client,
};