/** @module ldap */

/**
 * @typedef {object} LDAPMetadata
 * @description LDAPMetadata is an object containing metadata from ldap server.
 */
const LDAPMetadata = {};

/**
 * @class
 * @classdesc LdapClient is a client for ldap protocol in golang. It is a wrapper around the standard library ldap package.
 */
class LdapClient {
    /**
    * @method
    * @description CollectLdapMetadata collects metadata from ldap server.
    * @param {string} domain - The domain to collect metadata from.
    * @param {string} controller - The controller to collect metadata from.
    * @returns {LDAPMetadata} - The metadata from ldap server.
    * @throws {error} - The error encountered during metadata collection.
    * @example
    * let m = require('nuclei/ldap');
    * let c = m.LdapClient();
    * let metadata = c.CollectLdapMetadata('example.com', 'controller1');
    */
    CollectLdapMetadata(domain, controller) {
        // implemented in go
    };

    /**
    * @method
    * @description IsLdap checks if the given host and port are running ldap server.
    * @param {string} host - The host to check.
    * @param {int} port - The port to check.
    * @returns {boolean} - Whether the given host and port are running ldap server.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/ldap');
    * let c = m.LdapClient();
    * let isLdap = c.IsLdap('localhost', 389);
    * */
    IsLdap(host, port) {
        // implemented in go
    };
};

module.exports = {
    LdapClient: LdapClient,
};