

/**
 * Client is a client for Oracle database.
 * Internally client uses oracle/godror driver.
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
    * IsOracle checks if a host is running an Oracle server
    * @example
    * ```javascript
    * const oracle = require('nuclei/oracle');
    * const isOracle = oracle.IsOracle('acme.com', 1521);
    * log(toJSON(isOracle));
    * ```
    */
    public IsOracle(ctx: any, host: string, port: number): IsOracleResponse | null {
        return null;
    }
    

    /**
    * Connect connects to an Oracle database
    * @example
    * ```javascript
    * const oracle = require('nuclei/oracle');
    * const client = new oracle.OracleClient;
    * client.Connect('acme.com', 1521, 'XE', 'user', 'password');
    * ```
    */
    public Connect(ctx: any, host: string, port: number, serviceName: string, username: string, password: string): boolean | null {
        return null;
    }
    

    /**
    * ConnectWithDSN Method
    */
    public ConnectWithDSN(ctx: any, dsn: string): boolean | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to MS SQL database using given credentials and executes a query.
    * It returns the results of the query or an error if something goes wrong.
    * @example
    * ```javascript
    * const oracle = require('nuclei/oracle');
    * const client = new oracle.OracleClient;
    * const result = client.ExecuteQuery('acme.com', 1521, 'username', 'password', 'XE', 'SELECT @@version');
    * log(to_json(result));
    * ```
    */
    public ExecuteQuery(ctx: any, host: string, port: number, username: string): SQLResult | null | null {
        return null;
    }
    

    /**
    * ExecuteQueryWithDSN executes a query on an Oracle database using a DSN
    * @example
    * ```javascript
    * const oracle = require('nuclei/oracle');
    * const client = new oracle.OracleClient;
    * const result = client.ExecuteQueryWithDSN('oracle://user:password@host:port/service', 'SELECT @@version');
    * log(to_json(result));
    * ```
    */
    public ExecuteQueryWithDSN(ctx: any, dsn: string, query: string): SQLResult | null | null {
        return null;
    }
    

}



/**
 * IsOracleResponse is the response from the IsOracle function.
 * this is returned by IsOracle function.
 * @example
 * ```javascript
 * const oracle = require('nuclei/oracle');
 * const isOracle = oracle.IsOracle('acme.com', 1521);
 * ```
 */
export interface IsOracleResponse {
    
    IsOracle?: boolean,
    
    Banner?: string,
}



/**
 * SQLResult Interface
 */
export interface SQLResult {
    
    Count?: number,
    
    Columns?: string[],
}

