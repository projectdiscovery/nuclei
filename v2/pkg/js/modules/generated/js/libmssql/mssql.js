/**
 * @module mssql
 * @description mssql implements bindings for mssql protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class Client
 * @description Client is a client for MS SQL database. Internally client uses denisenkom/go-mssqldb driver.
 */
class Client {
    /**
     * @method Connect
     * @description Connects to MS SQL database using given credentials. The connection is closed after the function returns.
     * @param {string} host - The host of the MS SQL database.
     * @param {number} port - The port of the MS SQL database.
     * @param {string} username - The username for the MS SQL database.
     * @param {string} password - The password for the MS SQL database.
     * @returns {boolean} Returns true if connection is successful, false otherwise.
     * @throws {Error} If connection is unsuccessful.
     * @example
     * const client = new Client();
     * client.Connect('localhost', 1433, 'username', 'password');
     */
    Connect(host, port, username, password) {
        // Implementation here
    };

    /**
     * @method ConnectWithDB
     * @description Connects to MS SQL database using given credentials and database name. The connection is closed after the function returns.
     * @param {string} host - The host of the MS SQL database.
     * @param {number} port - The port of the MS SQL database.
     * @param {string} username - The username for the MS SQL database.
     * @param {string} password - The password for the MS SQL database.
     * @param {string} dbName - The name of the database.
     * @returns {boolean} Returns true if connection is successful, false otherwise.
     * @throws {Error} If connection is unsuccessful.
     * @example
     * const client = new Client();
     * client.ConnectWithDB('localhost', 1433, 'username', 'password', 'testDB');
     */
    ConnectWithDB(host, port, username, password, dbName) {
        // Implementation here
    };

    /**
     * @method IsMssql
     * @description Checks if the given host is running MS SQL database.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} Returns true if the host is running MS SQL database, false otherwise.
     * @throws {Error} If the check is unsuccessful.
     * @example
     * const client = new Client();
     * client.IsMssql('localhost', 1433);
     */
    IsMssql(host, port) {
        // Implementation here
    };
};


module.exports = {
    Client: Client,
};