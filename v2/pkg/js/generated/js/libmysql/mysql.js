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
    // ExecuteQuery connects to Mysql database using given credentials and database name.
    // and executes a query on the db.
    ExecuteQuery(host, port, username, password, dbName, query) {
        return string, error;
    };
    // IsMySQL checks if the given host is running MySQL database.
    // 
    // If the host is running MySQL database, it returns true.
    // If the host is not running MySQL database, it returns false.
    IsMySQL(host, port) {
        return bool, error;
    };
};


module.exports = {
    Client: Client,
};