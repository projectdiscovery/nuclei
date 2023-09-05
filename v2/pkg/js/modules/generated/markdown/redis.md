## redis 
---


`redis` implements bindings for `redis` protocol in javascript
to be used from nuclei scanner.





## Exported Functions

| Name | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
Connect |  Connect tries to connect redis server with password | `host`, `port`, `password` | `bool`, `error` |
GetServerInfo |  GetServerInfo returns the server info for a redis server | `host`, `port` | `string`, `error` |
GetServerInfoAuth |  GetServerInfoAuth returns the server info for a redis server | `host`, `port`, `password` | `string`, `error` |
IsAuthenticated |  IsAuthenticated checks if the redis server requires authentication | `host`, `port` | `bool`, `error` |
RunLuaScript |  RunLuaScript runs a lua script on | `host`, `port`, `password`, `script` | `error` |






