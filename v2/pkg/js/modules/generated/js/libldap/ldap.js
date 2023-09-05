/**
 * libldap implements bindings for ldap protocol in javascript
 * to be used from nuclei scanner.
 * 
 * @module Client
 */

/**
 * Client is a client for ldap protocol in golang.
 * It is a wrapper around the standard library ldap package.
 * 
 * @class
 */
class Client {
    /**
     * CollectLdapMetadata collects metadata from ldap server.
     * 
     * @param {string} domain - The domain to collect metadata from.
     * @param {string} controller - The controller to use for the collection.
     * @returns {Object} LDAPMetadata - The collected metadata.
     * @throws {Error} If an error occurs during the collection.
     */
    CollectLdapMetadata(domain, controller) {
        // return LDAPMetadata, error;
        throw new Error('Not implemented');
    };

    /**
     * IsLdap checks if the given host and port are running ldap server.
     * 
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} - True if the host and port are running an ldap server, false otherwise.
     * @throws {Error} If an error occurs during the check.
     */
    IsLdap(host, port) {
        // return bool, error;
        throw new Error('Not implemented');
    };
};

module.exports = {
    /**
     * The Client class
     * @type {Client}
     */
    Client: Client,
};