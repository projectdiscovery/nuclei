/**
 * @fileoverview This module implements bindings for the SMTP protocol in JavaScript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc This class represents a minimal SMTP client for nuclei scripts.
 */
class Client {
    /**
     * @method
     * @description This method checks if a host is running a SMTP server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} Returns true if the host is running a SMTP server, false otherwise.
     * @throws {Error} Throws an error if the check fails.
     */
    IsSMTP(host, port) {
        // Implementation of the method goes here.
        // If an error occurs, throw it instead of returning it.
    };
};

module.exports = {
    /** @exports Client */
    Client: Client,
};