/**
 * libmssql implements bindings for mssql protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * Client is a client for MS SQL database.
 * Internally client uses denisenkom/go-mssqldb driver.
 */
class Client {
    /**
     * Connect connects to MS SQL database using given credentials.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The connection is closed after the function returns.
     * 
     * @param {string} host - The host of the MS SQL database.
     * @param {number} port - The port of the MS SQL database.
     * @param {string} username - The username to connect to the MS SQL database.
     * @param {string} password - The password to connect to the MS SQL database.
     * @returns {boolean} - Returns true if connection is successful, otherwise throws an error.
     */
    Connect(host, port, username, password) {
        // Implementation goes here
    };

    /**
     * ConnectWithDB connects to MS SQL database using given credentials and database name.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The connection is closed after the function returns.
     * 
     * @param {string} host - The host of the MS SQL database.
     * @param {number} port - The port of the MS SQL database.
     * @param {string} username - The username to connect to the MS SQL database.
     * @param {string} password - The password to connect to the MS SQL database.
     * @param {string} dbName - The name of the database to connect to.
     * @returns {boolean} - Returns true if connection is successful, otherwise throws an error.
     */
    ConnectWithDB(host, port, username, password, dbName) {
        // Implementation goes here
    };

    /**
     * IsMssql checks if the given host is running MS SQL database.
     * If the host is running MS SQL database, it returns true.
     * If the host is not running MS SQL database, it throws an error.
     * 
     * @param {string} host - The host to check for MS SQL database.
     * @param {number} port - The port to check for MS SQL database.
     * @returns {boolean} - Returns true if the host is running MS SQL database, otherwise throws an error.
     */
    IsMssql(host, port) {
        // Implementation goes here
    };
};

module.exports = {
    Client: Client,
};