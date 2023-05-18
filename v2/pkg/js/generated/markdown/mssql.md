## libmssql 
---


`libmssql` implements bindings for `mssql` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a client for MS SQL database.    Internally client uses denisenkom/go-mssqldb driver.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `Connect` |  Connect connects to MS SQL database using given credentials.    If connection is successful, it returns true.  If connection is unsuccessful, it returns false and error.    The connection is closed after the function returns. | `host`, `port`, `username`, `password` | `bool`, `error` |
| `ConnectWithDB` |  ConnectWithDB connects to MS SQL database using given credentials and database name.    If connection is successful, it returns true.  If connection is unsuccessful, it returns false and error.    The connection is closed after the function returns. | `host`, `port`, `username`, `password`, `dbName` | `bool`, `error` |
| `IsMssql` |  IsMssql checks if the given host is running MS SQL database.    If the host is running MS SQL database, it returns true.  If the host is not running MS SQL database, it returns false. | `host`, `port` | `bool`, `error` |




