

/**
 * PGClient is a client for Postgres database.
 * Internally client uses go-pg/pg driver.
 * @example
 * ```javascript
 * const postgres = require('nuclei/postgres');
 * const client = new postgres.PGClient;
 * ```
 */
export class PGClient {
    

    // Constructor of PGClient
    constructor() {}
    /**
    * IsPostgres checks if the given host and port are running Postgres database.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * @example
    * ```javascript
    * const postgres = require('nuclei/postgres');
    * const isPostgres = postgres.IsPostgres('acme.com', 5432);
    * ```
    */
    public IsPostgres(host: string, port: number): boolean | null {
        return null;
    }
    

    /**
    * Connect connects to Postgres database using given credentials.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @example
    * ```javascript
    * const postgres = require('nuclei/postgres');
    * const client = new postgres.PGClient;
    * const connected = client.Connect('acme.com', 5432, 'username', 'password');
    * ```
    */
    public Connect(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * ConnectWithOptions connects to Postgres using the supplied connection options.
    */
    public ConnectWithOptions(opts: PostgresOptions): boolean | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to Postgres database using given credentials and database name.
    * and executes a query on the db.
    * If connection is successful, it returns the result of the query.
    * @example
    * ```javascript
    * const postgres = require('nuclei/postgres');
    * const client = new postgres.PGClient;
    * const result = client.ExecuteQuery('acme.com', 5432, 'username', 'password', 'dbname', 'select * from users');
    * log(to_json(result));
    * ```
    */
    public ExecuteQuery(host: string, port: number, username: string): SQLResult | null | null {
        return null;
    }
    

    /**
    * ConnectWithDB connects to Postgres database using given credentials and database name.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @example
    * ```javascript
    * const postgres = require('nuclei/postgres');
    * const client = new postgres.PGClient;
    * const connected = client.ConnectWithDB('acme.com', 5432, 'username', 'password', 'dbname');
    * ```
    */
    public ConnectWithDB(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

}



/**
 * PostgresOptions defines the connection options for a Postgres database.
 */
export interface PostgresOptions {
    
    Host?: string,
    
    Port?: number,
    
    Username?: string,
    
    Password?: string,
    
    DbName?: string,
    
    Timeout?: number,
    
    SSLMode?: string,
}



/**
 * SQLResult Interface
 */
export interface SQLResult {
    
    Count?: number,
    
    Columns?: string[],
}

