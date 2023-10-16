/** @module kerberos */

/**
 * @class
 * @classdesc KerberosClient is a kerberos client
 */
class KerberosClient {
    /**
    * @method
    * @description EnumerateUser returns true if the user exists in the domain. If the user is not found, false is returned. If the user is found, true is returned. Optionally, the AS-REP hash is also returned if discovered.
    * @param {string} domain - The domain to check.
    * @param {string} controller - The controller to use.
    * @param {string} username - The username to check.
    * @returns {EnumerateUserResponse} - The response of the enumeration.
    * @throws {error} - The error encountered during enumeration.
    * @example
    * let m = require('nuclei/kerberos');
    * let c = m.KerberosClient();
    * let response = c.EnumerateUser('domain', 'controller', 'username');
    */
    EnumerateUser(domain, controller, username) {
        // implemented in go
    };
};

/**
 * @typedef {object} EnumerateUserResponse
 * @description EnumerateUserResponse is the response object from the EnumerateUser method.
 */
const EnumerateUserResponse = {};

module.exports = {
    KerberosClient: KerberosClient,
};