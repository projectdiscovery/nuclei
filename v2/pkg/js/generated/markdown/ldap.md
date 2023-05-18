## libldap 
---


`libldap` implements bindings for `ldap` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a client for ldap protocol in golang.    It is a wrapper around the standard library ldap package.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `CollectLdapMetadata` |  CollectLdapMetadata collects metadata from ldap server. | domain, controller | error |
| `IsLdap` |  IsLdap checks if the given host and port are running ldap server. | host, port | bool, error |




