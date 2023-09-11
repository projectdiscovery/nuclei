/**
 * @module mysql
 */

/**
 * @class
 * @classdesc MySQLClient is a client for MySQL database. Internally client uses go-sql-driver/mysql driver.
 */
class MySQLClient {
    /**
     * @method
     * @description Connects to MySQL database using given credentials. The connection is closed after the function returns.
     * @param {string} host - The host of the MySQL database.
     * @param {number} port - The port of the MySQL database.
     * @param {string} username - The username for the MySQL database.
     * @param {string} password - The password for the MySQL database.
     * @returns {boolean} Returns true if connection is successful, otherwise false.
     * @throws {Error} If connection is unsuccessful.
     * @example
     * // Connect to MySQL database
     * let client = new MySQLClient();
     * client.Connect('localhost', 3306, 'root', 'password');
     */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
     * @method
     * @description Connects to MySQL database using given credentials and database name. The connection is closed after the function returns.
     * @param {string} host - The host of the MySQL database.
     * @param {number} port - The port of the MySQL database.
     * @param {string} username - The username for the MySQL database.
     * @param {string} password - The password for the MySQL database.
     * @param {string} dbName - The name of the database.
     * @returns {boolean} Returns true if connection is successful, otherwise false.
     * @throws {Error} If connection is unsuccessful.
     * @example
     * // Connect to MySQL database with a specific database
     * let client = new MySQLClient();
     * client.ConnectWithDB('localhost', 3306, 'root', 'password', 'myDatabase');
     */
    ConnectWithDB(host, port, username, password, dbName) {
        // implemented in go
    };

    /**
     * @method
     * @description Connects to Mysql database using given credentials and database name and executes a query on the db.
     * @param {string} host - The host of the MySQL database.
     * @param {number} port - The port of the MySQL database.
     * @param {string} username - The username for the MySQL database.
     * @param {string} password - The password for the MySQL database.
     * @param {string} dbName - The name of the database.
     * @param {string} query - The query to execute.
     * @returns {string} The result of the query.
     * @throws {Error} If execution of query is unsuccessful.
     * @example
     * // Execute a query on the MySQL database
     * let client = new MySQLClient();
     * client.ExecuteQuery('localhost', 3306, 'root', 'password', 'myDatabase', 'SELECT * FROM users');
     */
    ExecuteQuery(host, port, username, password, dbName, query) {
        // implemented in go
    };

    /**
     * @method
     * @description Checks if the given host is running MySQL database.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} Returns true if the host is running MySQL database, otherwise false.
     * @throws {Error} If check is unsuccessful.
     * @example
     * // Check if a host is running MySQL database
     * let client = new MySQLClient();
     * client.IsMySQL('localhost', 3306);
     */
    IsMySQL(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    MySQLClient: MySQLClient,
};