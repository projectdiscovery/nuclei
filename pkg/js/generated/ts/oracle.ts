

/**
 * IsOracleResponse is the response from the IsOracle function.
 * this is returned by IsOracle function.
 * @example
 * ```javascript
 * const oracle = require('nuclei/oracle');
 * const client = new oracle.OracleClient();
 * const isOracle = client.IsOracle('acme.com', 1521);
 * ```
 */
export interface IsOracleResponse {
    IsOracle?: boolean,
    Banner?: string,
}

/**
 * Client is a client for Oracle database.
 * Internally client uses go-ora driver.
 * @example
 * ```javascript
 * const oracle = require('nuclei/oracle');
 * const client = new oracle.OracleClient();
 * ```
 */
export class OracleClient {
    // Constructor of OracleClient
    constructor() {}

    /**
     * Connect connects to an Oracle database
     * @example
     * ```javascript
     * const oracle = require('nuclei/oracle');
     * const client = new oracle.OracleClient();
     * client.Connect('acme.com', 1521, 'XE', 'user', 'password');
     * ```
     */
    public Connect(host: string, port: number, serviceName: string, username: string, password: string): boolean | null {
        return null;
    }

    /**
     * ConnectWithDSN connects to an Oracle database using a DSN string
     * @example
     * ```javascript
     * const oracle = require('nuclei/oracle');
     * const client = new oracle.OracleClient();
     * client.ConnectWithDSN('oracle://user:password@host:port/service', 'SELECT @@version');
     * ```
     */
    public ConnectWithDSN(dsn: string): boolean | null {
        return null;
    }

    /**
     * IsOracle checks if a host is running an Oracle server
     * @example
     * ```javascript
     * const oracle = require('nuclei/oracle');
     * const isOracle = oracle.IsOracle('acme.com', 1521);
     * ```
     */
    public IsOracle(host: string, port: number): IsOracleResponse | null {
        return null;
    }

    /**
     * ExecuteQuery connects to Oracle database using given credentials and executes a query.
     * It returns the results of the query or an error if something goes wrong.
     * @example
     * ```javascript
     * const oracle = require('nuclei/oracle');
     * const client = new oracle.OracleClient();
     * const result = client.ExecuteQuery('acme.com', 1521, 'username', 'password', 'XE', 'SELECT * FROM dual');
     * log(to_json(result));
     * ```
     */
    public ExecuteQuery(host: string, port: number, username: string, password: string, dbName: string, query: string): SQLResult | null {
        return null;
    }

    /**
     * ExecuteQueryWithDSN executes a query on an Oracle database using a DSN
     * @example
     * ```javascript
     * const oracle = require('nuclei/oracle');
     * const client = new oracle.OracleClient();
     * const result = client.ExecuteQueryWithDSN('oracle://user:password@host:port/service', 'SELECT * FROM dual');
     * log(to_json(result));
     * ```
     */
    public ExecuteQueryWithDSN(dsn: string, query: string): SQLResult | null {
        return null;
    }
}

/**
 * SQLResult Interface
 */
export interface SQLResult {
    Count?: number,
    Columns?: string[],
    Rows?: any[],
}
