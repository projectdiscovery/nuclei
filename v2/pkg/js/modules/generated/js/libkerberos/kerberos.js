/**
 * @module kerberos
 * This module implements bindings for kerberos protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc This class represents a kerberos client.
 */
class KerberosClient {
    /**
     * @method
     * @name EnumerateUser
     * @description This method returns true if the user exists in the domain. If the user is not found, false is returned. If the user is found, true is returned. Optionally, the AS-REP hash is also returned if discovered.
     * @param {string} domain - The domain to be checked.
     * @param {string} controller - The controller to be used.
     * @param {string} username - The username to be checked.
     * @returns {Object} EnumerateUserResponse - The response from the enumeration of the user.
     * @throws {Error} If there is an error in the process.
     * @example
     * // Example usage of EnumerateUser
     * let client = new KerberosClient();
     * let response = client.EnumerateUser('example.com', 'controller1', 'user1');
     */
    EnumerateUser(domain, controller, username) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    KerberosClient: KerberosClient,
};