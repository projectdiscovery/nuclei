// libmysql implements bindings for mysql protocol in javascript
// to be used from nuclei scanner.

// Client is a client for MySQL database.
// 
// Internally client uses go-sql-driver/mysql driver.
class Client {
    // Connect connects to MySQL database using given credentials.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    // 
    // The connection is closed after the function returns.
    Connect(host, port, username, password) {
        return bool, error;
    };
    // ConnectWithDB connects to MySQL database using given credentials and database name.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    // 
    // The connection is closed after the function returns.
    ConnectWithDB(host, port, username, password, dbName) {
        return bool, error;
    };
};


module.exports = {
    Client: Client,
};