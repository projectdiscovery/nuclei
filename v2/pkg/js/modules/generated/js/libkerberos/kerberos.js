/**
 * @fileoverview This module implements bindings for kerberos protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class Class representing a kerberos client.
 */
class Client {
    /**
     * EnumerateUser checks if the user exists in the domain.
     * If the user is not found, false is returned.
     * If the user is found, true is returned. Optionally, the AS-REP
     * hash is also returned if discovered.
     * 
     * @param {string} domain - The domain to check the user.
     * @param {string} controller - The controller to use.
     * @param {string} username - The username to check.
     * @return {Object} EnumerateUserResponse - The response from the enumeration.
     * @throws {Error} If there is an error during the process.
     */
    EnumerateUser(domain, controller, username) {
        // Implementation goes here
    };
};

module.exports = {
    Client: Client,
};