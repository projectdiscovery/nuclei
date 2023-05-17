// libldap implements bindings for ldap protocol in javascript
// to be used from nuclei scanner.

// Client is a client for ldap protocol in golang.
// 
// It is a wrapper around the standard library ldap package.
class Client {
    // CollectLdapMetadata collects metadata from ldap server.
    CollectLdapMetadata(domain, controller) {
        return error;
    };
    // IsLdap checks if the given host and port are running ldap server.
    IsLdap(host, port) {
        return bool, error;
    };
};


module.exports = {
    Client: Client,
};