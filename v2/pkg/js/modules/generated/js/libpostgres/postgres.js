/**
 * @module postgres
 * @description postgres implements bindings for postgres protocol in javascript to be used from nuclei scanner.
 */

/**
 * @class Client
 * @description Client is a client for Postgres database. Internally client uses go-pg/pg driver.
 */
class Client {
    /**
     * @method Connect
     * @description Connects to Postgres database using given credentials. The connection is closed after the function returns.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username to connect to the Postgres database.
     * @param {string} password - The password to connect to the Postgres database.
     * @returns {boolean} Returns true if connection is successful, false otherwise.
     * @throws {Error} Throws an error if connection is unsuccessful.
     * @example
     * Connect('localhost', 5432, 'user', 'password');
     */
    Connect(host, port, username, password) {
        // implementation here
    };

    /**
     * @method ConnectWithDB
     * @description Connects to Postgres database using given credentials and database name. The connection is closed after the function returns.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username to connect to the Postgres database.
     * @param {string} password - The password to connect to the Postgres database.
     * @param {string} dbName - The name of the database.
     * @returns {boolean} Returns true if connection is successful, false otherwise.
     * @throws {Error} Throws an error if connection is unsuccessful.
     * @example
     * ConnectWithDB('localhost', 5432, 'user', 'password', 'myDatabase');
     */
    ConnectWithDB(host, port, username, password, dbName) {
        // implementation here
    };

    /**
     * @method ExecuteQuery
     * @description Connects to Postgres database using given credentials and database name and executes a query on the db.
     * @param {string} host - The host of the Postgres database.
     * @param {number} port - The port of the Postgres database.
     * @param {string} username - The username to connect to the Postgres database.
     * @param {string} password - The password to connect to the Postgres database.
     * @param {string} dbName - The name of the database.
     * @param {string} query - The query to execute on the database.
     * @returns {string} Returns the result of the query.
     * @throws {Error} Throws an error if connection or query execution is unsuccessful.
     * @example
     * ExecuteQuery('localhost', 5432, 'user', 'password', 'myDatabase', 'SELECT * FROM users');
     */
    ExecuteQuery(host, port, username, password, dbName, query) {
        // implementation here
    };

    /**
     * @method IsPostgres
     * @description Checks if the given host and port are running Postgres database.
     * @param {string} host - The host to check.
     * @param {number} port - The port to check.
     * @returns {boolean} Returns true if the given host and port are running Postgres database, false otherwise.
     * @throws {Error} Throws an error if connection is unsuccessful.
     * @example
     * IsPostgres('localhost', 5432);
     */
    IsPostgres(host, port) {
        // implementation here
    };
};


module.exports = {
    Client: Client,
};