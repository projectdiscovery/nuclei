

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
    

}

