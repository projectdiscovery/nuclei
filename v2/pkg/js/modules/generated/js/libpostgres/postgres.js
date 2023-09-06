/**
 * @module postgres
 * This module implements bindings for postgres protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class
 * @classdesc PGClient is a client for Postgres database. Internally client uses go-pg/pg driver.
 */
class PGClient {
    /**
     * @method
     * @description Connects to Postgres database using given credentials. The connection is closed after the function returns.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username for the Postgres database.
     * @param {string} password - The password for the Postgres database.
     * @returns {boolean} Returns true if connection is successful, otherwise false.
     * @throws {Error} If connection is unsuccessful.
     */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
     * @method
     * @description Connects to Postgres database using given credentials and database name. The connection is closed after the function returns.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username for the Postgres database.
     * @param {string} password - The password for the Postgres database.
     * @param {string} dbName - The name of the database.
     * @returns {boolean} Returns true if connection is successful, otherwise false.
     * @throws {Error} If connection is unsuccessful.
     */
    ConnectWithDB(host, port, username, password, dbName) {
        // implemented in go
    };

    /**
     * @method
     * @description Connects to Postgres database using given credentials and database name and executes a query on the db.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username for the Postgres database.
     * @param {string} password - The password for the Postgres database.
     * @param {string} dbName - The name of the database.
     * @param {string} query - The query to be executed.
     * @returns {string} Returns the result of the query execution.
     * @throws {Error} If connection is unsuccessful or query execution fails.
     */
    ExecuteQuery(host, port, username, password, dbName, query) {
        // implemented in go
    };

    /**
     * @method
     * @description Checks if the given host and port are running Postgres database.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @returns {boolean} Returns true if connection is successful, otherwise false.
     * @throws {Error} If connection is unsuccessful.
     */
    IsPostgres(host, port) {
        // implemented in go
    };
};

// ReadOnly DONOT EDIT
module.exports = {
    PGClient: PGClient,
};