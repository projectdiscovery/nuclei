/** @module mssql */

/**
 * @class
 * @classdesc MSSQLClient is a client for MS SQL database. Internally client uses denisenkom/go-mssqldb driver.
 */
class MSSQLClient {
    /**
    * @method
    * @description Connect connects to MS SQL database using given credentials. If connection is successful, it returns true. If connection is unsuccessful, it returns false and error. The connection is closed after the function returns.
    * @param {string} host - The host of the MS SQL database.
    * @param {int} port - The port of the MS SQL database.
    * @param {string} username - The username to connect to the MS SQL database.
    * @param {string} password - The password to connect to the MS SQL database.
    * @returns {bool} - The status of the connection.
    * @throws {error} - The error encountered during connection.
    * @example
    * let m = require('nuclei/mssql');
    * let c = m.MSSQLClient();
    * let isConnected = c.Connect('localhost', 1433, 'username', 'password');
    */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
    * @method
    * @description ConnectWithDB connects to MS SQL database using given credentials and database name. If connection is successful, it returns true. If connection is unsuccessful, it returns false and error. The connection is closed after the function returns.
    * @param {string} host - The host of the MS SQL database.
    * @param {int} port - The port of the MS SQL database.
    * @param {string} username - The username to connect to the MS SQL database.
    * @param {string} password - The password to connect to the MS SQL database.
    * @param {string} dbName - The name of the database to connect to.
    * @returns {bool} - The status of the connection.
    * @throws {error} - The error encountered during connection.
    * @example
    * let m = require('nuclei/mssql');
    * let c = m.MSSQLClient();
    * let isConnected = c.ConnectWithDB('localhost', 1433, 'username', 'password', 'myDatabase');
    */
    ConnectWithDB(host, port, username, password, dbName) {
        // implemented in go
    };

    /**
    * @method
    * @description IsMssql checks if the given host is running MS SQL database. If the host is running MS SQL database, it returns true. If the host is not running MS SQL database, it returns false.
    * @param {string} host - The host to check.
    * @param {int} port - The port to check.
    * @returns {bool} - The status of the check.
    * @throws {error} - The error encountered during the check.
    * @example
    * let m = require('nuclei/mssql');
    * let c = m.MSSQLClient();
    * let isMssql = c.IsMssql('localhost', 1433);
    */
    IsMssql(host, port) {
        // implemented in go
    };
};

module.exports = {
    MSSQLClient: MSSQLClient,
};