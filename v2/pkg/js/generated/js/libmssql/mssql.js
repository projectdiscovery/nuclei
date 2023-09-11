/**
 * @module mssql
 */

/**
 * @class
 * @classdesc Client is a client for MS SQL database.
 * Internally client uses denisenkom/go-mssqldb driver.
 */
class MSSQLClient {
    /**
     * @method
     * @description Connect connects to MS SQL database using given credentials.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The connection is closed after the function returns.
     * @param {string} host - The host of the MS SQL database.
     * @param {number} port - The port of the MS SQL database.
     * @param {string} username - The username to connect to the MS SQL database.
     * @param {string} password - The password to connect to the MS SQL database.
     * @returns {boolean} - Returns true if connection is successful, otherwise throws an error.
     * @throws {Error} If connection is unsuccessful.
     * @example
     * // returns true
     * MSSQLClient.Connect('localhost', 1433, 'username', 'password');
     */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
     * @method
     * @description ConnectWithDB connects to MS SQL database using given credentials and database name.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The connection is closed after the function returns.
     * @param {string} host - The host of the MS SQL database.
     * @param {number} port - The port of the MS SQL database.
     * @param {string} username - The username to connect to the MS SQL database.
     * @param {string} password - The password to connect to the MS SQL database.
     * @param {string} dbName - The name of the database to connect to.
     * @returns {boolean} - Returns true if connection is successful, otherwise throws an error.
     * @throws {Error} If connection is unsuccessful.
     * @example
     * // returns true
     * MSSQLClient.ConnectWithDB('localhost', 1433, 'username', 'password', 'myDatabase');
     */
    ConnectWithDB(host, port, username, password, dbName) {
        // implemented in go
    };

    /**
     * @method
     * @description IsMssql checks if the given host is running MS SQL database.
     * If the host is running MS SQL database, it returns true.
     * If the host is not running MS SQL database, it throws an error.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} - Returns true if the host is running MS SQL database, otherwise throws an error.
     * @throws {Error} If the host is not running MS SQL database.
     * @example
     * // returns true
     * MSSQLClient.IsMssql('localhost', 1433);
     */
    IsMssql(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    MSSQLClient: MSSQLClient,
};