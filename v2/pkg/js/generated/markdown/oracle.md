## liboracle 
---


`liboracle` implements bindings for `oracle` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a minimal Oracle client for nuclei scripts.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `IsOracle` |  IsOracle checks if a host is running an Oracle server. | `host`, `port` | `IsOracleResponse`, `error` |




## Exported Types Fields
### IsOracleResponse

| Name | Type | 
|--------|-------------|
| Banner | `string` |
| IsOracle | `bool` |
