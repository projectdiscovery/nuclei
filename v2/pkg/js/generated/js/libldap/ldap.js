/**
 * @module ldap
 */

/**
 * @class LdapClient
 * @description Client is a client for ldap protocol in golang.
 * It is a wrapper around the standard library ldap package.
 */
class LdapClient {
    /**
     * @method CollectLdapMetadata
     * @description collects metadata from ldap server.
     * @param {string} domain - The domain to collect metadata from.
     * @param {string} controller - The controller to use for collection.
     * @returns {Object} LDAPMetadata - The collected metadata.
     * @throws {Error} If an error occurs during collection.
     * @example
     * let client = new LdapClient();
     * let metadata = client.CollectLdapMetadata("example.com", "controller1");
     */
    CollectLdapMetadata(domain, controller) {
        // implemented in go
    };

    /**
     * @method IsLdap
     * @description checks if the given host and port are running ldap server.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} - Returns true if the host and port are running an ldap server, false otherwise.
     * @throws {Error} If an error occurs during the check.
     * @example
     * let client = new LdapClient();
     * let isLdap = client.IsLdap("localhost", 389);
     */
    IsLdap(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    LdapClient: LdapClient,
};