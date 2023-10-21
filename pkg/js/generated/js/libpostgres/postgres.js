/** @module postgres */

/**
 * @class
 * @classdesc PGClient is a client for Postgres database. Internally client uses go-pg/pg driver.
 */
class PGClient {
    /**
    * @method
    * @description Connect connects to Postgres database using given credentials. The connection is closed after the function returns.
    * @param {string} host - The host of the Postgres database.
    * @param {int} port - The port of the Postgres database.
    * @param {string} username - The username to connect to the Postgres database.
    * @param {string} password - The password to connect to the Postgres database.
    * @returns {bool} - If connection is successful, it returns true.
    * @throws {error} - If connection is unsuccessful, it returns the error.
    * @example
    * let m = require('nuclei/postgres');
    * let c = m.PGClient();
    * let isConnected = c.Connect('localhost', 5432, 'username', 'password');
    */
    Connect(host, port, username, password) {
        // implemented in go
    };

    /**
    * @method
    * @description ConnectWithDB connects to Postgres database using given credentials and database name. The connection is closed after the function returns.
    * @param {string} host - The host of the Postgres database.
    * @param {int} port - The port of the Postgres database.
    * @param {string} username - The username to connect to the Postgres database.
    * @param {string} password - The password to connect to the Postgres database.
    * @param {string} dbName - The name of the database to connect to.
    * @returns {bool} - If connection is successful, it returns true.
    * @throws {error} - If connection is unsuccessful, it returns the error.
    * @example
    * let m = require('nuclei/postgres');
    * let c = m.PGClient();
    * let isConnected = c.ConnectWithDB('localhost', 5432, 'username', 'password', 'mydb');
    */
    ConnectWithDB(host, port, username, password, dbName) {
        // implemented in go
    };

    /**
    * @method
    * @description ExecuteQuery connects to Postgres database using given credentials and database name and executes a query on the db.
    * @param {string} host - The host of the Postgres database.
    * @param {int} port - The port of the Postgres database.
    * @param {string} username - The username to connect to the Postgres database.
    * @param {string} password - The password to connect to the Postgres database.
    * @param {string} dbName - The name of the database to connect to.
    * @param {string} query - The query to execute on the database.
    * @returns {string} - The result of the query execution.
    * @throws {error} - If query execution is unsuccessful, it returns the error.
    * @example
    * let m = require('nuclei/postgres');
    * let c = m.PGClient();
    * let result = c.ExecuteQuery('localhost', 5432, 'username', 'password', 'mydb', 'SELECT * FROM users');
    */
    ExecuteQuery(host, port, username, password, dbName, query) {
        // implemented in go
    };

    /**
    * @method
    * @description IsPostgres checks if the given host and port are running Postgres database.
    * @param {string} host - The host to check.
    * @param {int} port - The port to check.
    * @returns {bool} - If the host and port are running Postgres database, it returns true.
    * @throws {error} - If the check is unsuccessful, it returns the error.
    * @example
    * let m = require('nuclei/postgres');
    * let c = m.PGClient();
    * let isPostgres = c.IsPostgres('localhost', 5432);
    */
    IsPostgres(host, port) {
        // implemented in go
    };
};

module.exports = {
    PGClient: PGClient,
};