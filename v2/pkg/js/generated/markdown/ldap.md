## ldap 
---


`ldap` implements bindings for `ldap` protocol in javascript
to be used from nuclei scanner.



## Types

### LdapClient

 Client is a client for ldap protocol in golang.    It is a wrapper around the standard library ldap package.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `CollectLdapMetadata` |  CollectLdapMetadata collects metadata from ldap server. | `domain`, `controller` | `LDAPMetadata`, `error` |
| `IsLdap` |  IsLdap checks if the given host and port are running ldap server. | `host`, `port` | `bool`, `error` |




## Exported Types Fields
### LDAPMetadata

| Name | Type | 
|--------|-------------|
| BaseDN | `string` |
| DefaultNamingContext | `string` |
| DnsHostName | `string` |
| Domain | `string` |
| DomainControllerFunctionality | `string` |
| DomainFunctionality | `string` |
| ForestFunctionality | `string` |




