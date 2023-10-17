/** @module mysql */

/**
 * @class
 * @classdesc MySQLClient is a client for MySQL database. Internally client uses go-sql-driver/mysql driver.
 */
class MySQLClient {
    /**
    * @method
    * @description Connect connects to MySQL database using given credentials. If connection is successful, it returns true. If connection is unsuccessful, it returns false and error. The connection is closed after the function returns.
    * @param {string} host - The host of the MySQL database.
    * @param {int} port - The port of the MySQL database.
    * @param {string} username - The username to connect to the MySQL database.
    * @param {string} password - The password to connect to the MySQL database.
    * @returns {bool} - The result of the connection attempt.
    * @throws {error} - The error encountered during connection attempt.
    * @example
    * let m = require('nuclei/mysql');
    * let c = m.MySQLClient();
    * let result = c.Connect('localhost', 3306, 'root', 'password');
    */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
    * @method
    * @description ConnectWithDB connects to MySQL database using given credentials and database name. If connection is successful, it returns true. If connection is unsuccessful, it returns false and error. The connection is closed after the function returns.
    * @param {string} host - The host of the MySQL database.
    * @param {int} port - The port of the MySQL database.
    * @param {string} username - The username to connect to the MySQL database.
    * @param {string} password - The password to connect to the MySQL database.
    * @param {string} dbName - The name of the database to connect to.
    * @returns {bool} - The result of the connection attempt.
    * @throws {error} - The error encountered during connection attempt.
    * @example
    * let m = require('nuclei/mysql');
    * let c = m.MySQLClient();
    * let result = c.ConnectWithDB('localhost', 3306, 'root', 'password', 'mydb');
    */
    ConnectWithDB(host, port, username, password, dbName) {
        // implemented in go
    };

    /**
    * @method
    * @description ExecuteQuery connects to Mysql database using given credentials and database name and executes a query on the db.
    * @param {string} host - The host of the MySQL database.
    * @param {int} port - The port of the MySQL database.
    * @param {string} username - The username to connect to the MySQL database.
    * @param {string} password - The password to connect to the MySQL database.
    * @param {string} dbName - The name of the database to connect to.
    * @param {string} query - The query to execute on the database.
    * @returns {string} - The result of the query execution.
    * @throws {error} - The error encountered during query execution.
    * @example
    * let m = require('nuclei/mysql');
    * let c = m.MySQLClient();
    * let result = c.ExecuteQuery('localhost', 3306, 'root', 'password', 'mydb', 'SELECT * FROM users');
    */
    ExecuteQuery(host, port, username, password, dbName, query) {
        // implemented in go
    };

    /**
    * @method
    * @description IsMySQL checks if the given host is running MySQL database. If the host is running MySQL database, it returns true. If the host is not running MySQL database, it returns false.
    * @param {string} host - The host to check.
    * @param {int} port - The port to check.
    * @returns {bool} - The result of the check.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/mysql');
    * let c = m.MySQLClient();
    * let result = c.IsMySQL('localhost', 3306);
    */
    IsMySQL(host, port) {
        // implemented in go
    };
};

module.exports = {
    MySQLClient: MySQLClient,
};