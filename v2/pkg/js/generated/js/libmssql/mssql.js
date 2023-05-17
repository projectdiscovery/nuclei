// libmssql implements bindings for mssql protocol in javascript
// to be used from nuclei scanner.

// Client is a client for MS SQL database.
// 
// Internally client uses denisenkom/go-mssqldb driver.
class Client {
    // Connect connects to MS SQL database using given credentials.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    // 
    // The connection is closed after the function returns.
    Connect(host, port, username, password) {
        return bool, error;
    };
    // ConnectWithDB connects to MS SQL database using given credentials and database name.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    // 
    // The connection is closed after the function returns.
    ConnectWithDB(host, port, username, password, dbName) {
        return bool, error;
    };
    // IsMssql checks if the given host is running MS SQL database.
    // 
    // If the host is running MS SQL database, it returns true.
    // If the host is not running MS SQL database, it returns false.
    IsMssql(host, port) {
        return bool, error;
    };
};


module.exports = {
    Client: Client,
};