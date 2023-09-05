/**
 * libmysql implements bindings for mysql protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * Client is a client for MySQL database.
 * Internally client uses go-sql-driver/mysql driver.
 */
class Client {
    /**
     * Connect connects to MySQL database using given credentials.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The connection is closed after the function returns.
     * @param {string} host - The host of the MySQL database.
     * @param {number} port - The port of the MySQL database.
     * @param {string} username - The username for the MySQL database.
     * @param {string} password - The password for the MySQL database.
     * @returns {boolean} - Returns true if connection is successful.
     * @throws {Error} - Throws an error if connection is unsuccessful.
     */
    Connect(host, port, username, password) {
        // Implementation here
    };

    /**
     * ConnectWithDB connects to MySQL database using given credentials and database name.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The connection is closed after the function returns.
     * @param {string} host - The host of the MySQL database.
     * @param {number} port - The port of the MySQL database.
     * @param {string} username - The username for the MySQL database.
     * @param {string} password - The password for the MySQL database.
     * @param {string} dbName - The name of the database to connect to.
     * @returns {boolean} - Returns true if connection is successful.
     * @throws {Error} - Throws an error if connection is unsuccessful.
     */
    ConnectWithDB(host, port, username, password, dbName) {
        // Implementation here
    };

    /**
     * ExecuteQuery connects to Mysql database using given credentials and database name.
     * and executes a query on the db.
     * @param {string} host - The host of the MySQL database.
     * @param {number} port - The port of the MySQL database.
     * @param {string} username - The username for the MySQL database.
     * @param {string} password - The password for the MySQL database.
     * @param {string} dbName - The name of the database to connect to.
     * @param {string} query - The query to execute on the database.
     * @returns {string} - Returns the result of the query.
     * @throws {Error} - Throws an error if the query execution is unsuccessful.
     */
    ExecuteQuery(host, port, username, password, dbName, query) {
        // Implementation here
    };

    /**
     * IsMySQL checks if the given host is running MySQL database.
     * If the host is running MySQL database, it returns true.
     * If the host is not running MySQL database, it throws an error.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} - Returns true if the host is running MySQL database.
     * @throws {Error} - Throws an error if the host is not running MySQL database.
     */
    IsMySQL(host, port) {
        // Implementation here
    };
};

module.exports = {
    Client: Client,
};