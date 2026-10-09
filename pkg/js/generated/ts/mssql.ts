/**
 * Client is a client for MS SQL database.
 * Internally client uses microsoft/go-mssqldb driver.
 * @example
 * ```javascript
 * const mssql = require('nuclei/mssql');
 * const client = new mssql.MSSQLClient;
 * ```
 */
export class MSSQLClient {
    

    // Constructor of MSSQLClient
    constructor() {}
    /**
    * Connect connects to MS SQL database using given credentials.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @example
    * ```javascript
    * const mssql = require('nuclei/mssql');
    * const client = new mssql.MSSQLClient;
    * const connected = client.Connect('acme.com', 1433, 'username', 'password');
    * ```
    */
    public Connect(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * ConnectWithDB connects to MS SQL database using given credentials and database name.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @example
    * ```javascript
    * const mssql = require('nuclei/mssql');
    * const client = new mssql.MSSQLClient;
    * const connected = client.ConnectWithDB('acme.com', 1433, 'username', 'password', 'master');
    * ```
    */
    public ConnectWithDB(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * ConnectWithOptions connects to MS SQL using the supplied connection options.
    */
    public ConnectWithOptions(opts: MSSQLOptions): boolean | null {
        return null;
    }
    

    /**
    * IsMssql checks if the given host is running MS SQL database.
    * If the host is running MS SQL database, it returns true.
    * If the host is not running MS SQL database, it returns false.
    * @example
    * ```javascript
    * const mssql = require('nuclei/mssql');
    * const isMssql = mssql.IsMssql('acme.com', 1433);
    * ```
    */
    public IsMssql(host: string, port: number): boolean | null {
        return null;
    }
    

    /**
    * FingerprintMssql gathers MSSQL pre-login fingerprint data from the target.
    * @example
    * ```javascript
    * const mssql = require('nuclei/mssql');
    * const info = mssql.FingerprintMssql('acme.com', 1433);
    * log(to_json(info));
    * ```
    */
    public FingerprintMssql(host: string, port: number): MSSQLInfo | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to MS SQL database using given credentials and executes a query.
    * It returns the results of the query or an error if something goes wrong.
    * @example
    * ```javascript
    * const mssql = require('nuclei/mssql');
    * const client = new mssql.MSSQLClient;
    * const result = client.ExecuteQuery('acme.com', 1433, 'username', 'password', 'master', 'SELECT @@version');
    * log(to_json(result));
    * ```
    */
    public ExecuteQuery(host: string, port: number, username: string): SQLResult | null | null {
        return null;
    }
    

}



/**
 * MSSQLOptions defines the connection options for an MS SQL database.
 */
export interface MSSQLOptions {
    
    Host?: string,
    
    Port?: number,
    
    Username?: string,
    
    Password?: string,
    
    DbName?: string,
    
    Timeout?: number,
}



/**
 * SQLResult Interface
 */
export interface SQLResult {
    
    Count?: number,
    
    Columns?: string[],
}


/**
 * MSSQLInfo contains TDS pre-login fingerprint data.
 */
export interface MSSQLInfo {
    host?: string,
    ip?: string,
    port?: number,
    protocol?: string,
    tls?: boolean,
    transport?: string,
    version?: string,
    majorVersion?: number,
    minorVersion?: number,
    buildNumber?: number,
    encryption?: number,
    encryptionMode?: string,
    mars?: boolean,
    instanceMatches?: boolean,
    raw?: string,
}
