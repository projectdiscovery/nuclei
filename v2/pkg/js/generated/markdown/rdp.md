## rdp 
---


`rdp` implements bindings for `rdp` protocol in javascript
to be used from nuclei scanner.



## Types

### RDPClient

 RDPClient is a client for rdp servers

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `CheckRDPAuth` |  CheckRDPAuth checks if the given host and port are running rdp server  with authentication and returns their metadata. | `host`, `port` | `CheckRDPAuthResponse`, `error` |
| `IsRDP` |  IsRDP checks if the given host and port are running rdp server.    If connection is successful, it returns true.  If connection is unsuccessful, it returns false and error.    The Name of the OS is also returned if the connection is successful. | `host`, `port` | `IsRDPResponse`, `error` |




## Exported Types Fields
### CheckRDPAuthResponse

| Name | Type | 
|--------|-------------|
| Auth | `bool` |
| PluginInfo | `` |
### IsRDPResponse

| Name | Type | 
|--------|-------------|
| IsRDP | `bool` |
| OS | `string` |




