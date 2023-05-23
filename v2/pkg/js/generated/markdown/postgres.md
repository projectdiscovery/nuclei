## libpostgres 
---


`libpostgres` implements bindings for `postgres` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a client for Postgres database.    Internally client uses go-pg/pg driver.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `Connect` |  Connect connects to Postgres database using given credentials.    If connection is successful, it returns true.  If connection is unsuccessful, it returns false and error.    The connection is closed after the function returns. | `host`, `port`, `username`, `password` | `bool`, `error` |
| `ConnectWithDB` |  ConnectWithDB connects to Postgres database using given credentials and database name.    If connection is successful, it returns true.  If connection is unsuccessful, it returns false and error.    The connection is closed after the function returns. | `host`, `port`, `username`, `password`, `dbName` | `bool`, `error` |
| `ExecuteQuery` |  ExecuteQuery connects to Postgres database using given credentials and database name.  and executes a query on the db. | `host`, `port`, `username`, `password`, `dbName`, `query` | `string`, `error` |
| `IsPostgres` |  IsPostgres checks if the given host and port are running Postgres database.    If connection is successful, it returns true.  If connection is unsuccessful, it returns false and error. | `host`, `port` | `bool`, `error` |








