// libpostgres implements bindings for postgres protocol in javascript
// to be used from nuclei scanner.

// Client is a client for Postgres database.
// 
// Internally client uses go-pg/pg driver.
class Client {
    // Connect connects to Postgres database using given credentials.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    // 
    // The connection is closed after the function returns.
    Connect(host, port, username, password) {
        return bool, error;
    };
    // ConnectWithDB connects to Postgres database using given credentials and database name.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    // 
    // The connection is closed after the function returns.
    ConnectWithDB(host, port, username, password, dbName) {
        return bool, error;
    };
    // ExecuteQuery connects to Postgres database using given credentials and database name.
    // and executes a query on the db.
    ExecuteQuery(host, port, username, password, dbName, query) {
        return string, error;
    };
    // IsPostgres checks if the given host and port are running Postgres database.
    // 
    // If connection is successful, it returns true.
    // If connection is unsuccessful, it returns false and error.
    IsPostgres(host, port) {
        return bool, error;
    };
};


module.exports = {
    Client: Client,
};