/**
 * libpostgres implements bindings for postgres protocol in javascript
 * to be used from nuclei scanner.
 */

/**
 * Client is a client for Postgres database.
 * Internally client uses go-pg/pg driver.
 * @class
 */
class Client {
    /**
     * Connect connects to Postgres database using given credentials.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The connection is closed after the function returns.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username to connect to the Postgres database.
     * @param {string} password - The password to connect to the Postgres database.
     * @returns {boolean} - Returns true if connection is successful, otherwise throws an error.
     */
    Connect(host, port, username, password) {
        // Implementation goes here
    };

    /**
     * ConnectWithDB connects to Postgres database using given credentials and database name.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * The connection is closed after the function returns.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username to connect to the Postgres database.
     * @param {string} password - The password to connect to the Postgres database.
     * @param {string} dbName - The name of the database to connect to.
     * @returns {boolean} - Returns true if connection is successful, otherwise throws an error.
     */
    ConnectWithDB(host, port, username, password, dbName) {
        // Implementation goes here
    };

    /**
     * ExecuteQuery connects to Postgres database using given credentials and database name.
     * and executes a query on the db.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username to connect to the Postgres database.
     * @param {string} password - The password to connect to the Postgres database.
     * @param {string} dbName - The name of the database to connect to.
     * @param {string} query - The query to execute on the database.
     * @returns {string} - Returns the result of the query execution, otherwise throws an error.
     */
    ExecuteQuery(host, port, username, password, dbName, query) {
        // Implementation goes here
    };

    /**
     * IsPostgres checks if the given host and port are running Postgres database.
     * If connection is successful, it returns true.
     * If connection is unsuccessful, it throws an error.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @returns {boolean} - Returns true if the host and port are running Postgres database, otherwise throws an error.
     */
    IsPostgres(host, port) {
        // Implementation goes here
    };
};

module.exports = {
    Client: Client,
};