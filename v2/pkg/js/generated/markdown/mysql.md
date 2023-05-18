## libmysql 
---


`libmysql` implements bindings for `mysql` protocol in javascript
to be used from nuclei scanner.



## Types

### Client

 Client is a client for MySQL database.    Internally client uses go-sql-driver/mysql driver.

| Method | Description | Arguments | Returns |
|--------|-------------|-----------|---------|
| `Connect` |  Connect connects to MySQL database using given credentials.    If connection is successful, it returns true.  If connection is unsuccessful, it returns false and error.    The connection is closed after the function returns. | host, port, username, password | bool, error |
| `ConnectWithDB` |  ConnectWithDB connects to MySQL database using given credentials and database name.    If connection is successful, it returns true.  If connection is unsuccessful, it returns false and error.    The connection is closed after the function returns. | host, port, username, password, dbName | bool, error |
| `IsMySQL` |  IsMySQL checks if the given host is running MySQL database.    If the host is running MySQL database, it returns true.  If the host is not running MySQL database, it returns false. | host, port | bool, error |




