## libkerberos 
---


`libkerberos` implements bindings for `kerberos` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `EnumerateUser` |  EnumerateUser returns true if the user exists in the domain    If the user is not found, false is returned.  If the user is found, true is returned. Optionally, the AS-REP  hash is also returned if discovered. | domain, controller, username | EnumerateUserResponse, error |

