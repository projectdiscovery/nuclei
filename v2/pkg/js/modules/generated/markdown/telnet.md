## telnet 
---


`telnet` implements bindings for `telnet` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a minimal Telnet client for nuclei scripts.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `IsTelnet` |  IsTelnet checks if a host is running a Telnet server. | `host`, `port` | `IsTelnetResponse`, `error` |




## Exported Types Fields
### IsTelnetResponse

| Name | Type | 
|--------|-------------|
| Banner | `string` |
| IsTelnet | `bool` |




