

/**
 * BuildDSN builds a MySQL data source name (DSN) from the given options.
 * @example
 * ```javascript
 * const mysql = require('nuclei/mysql');
 * const options = new mysql.MySQLOptions();
 * options.Host = 'acme.com';
 * options.Port = 3306;
 * const dsn = mysql.BuildDSN(options);
 * ```
 */
export function BuildDSN(opts: MySQLOptions): string | null {
    return null;
}



/**
 * MySQLClient is a client for MySQL database.
 * Internally client uses go-sql-driver/mysql driver.
 * @example
 * ```javascript
 * const mysql = require('nuclei/mysql');
 * const client = new mysql.MySQLClient;
 * ```
 */
export class MySQLClient {
    

    // Constructor of MySQLClient
    constructor() {}
    /**
    * IsMySQL checks if the given host is running MySQL database.
    * If the host is running MySQL database, it returns true.
    * If the host is not running MySQL database, it returns false.
    * @example
    * ```javascript
    * const mysql = require('nuclei/mysql');
    * const isMySQL = mysql.IsMySQL('acme.com', 3306);
    * ```
    */
    public IsMySQL(host: string, port: number): boolean | null {
        return null;
    }
    

    /**
    * Connect connects to MySQL database using given credentials.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @example
    * ```javascript
    * const mysql = require('nuclei/mysql');
    * const client = new mysql.MySQLClient;
    * const connected = client.Connect('acme.com', 3306, 'username', 'password');
    * ```
    */
    public Connect(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * returns MySQLInfo when fingerpint is successful
    * @example
    * ```javascript
    * const mysql = require('nuclei/mysql');
    * const info = mysql.FingerprintMySQL('acme.com', 3306);
    * log(to_json(info));
    * ```
    */
    public FingerprintMySQL(host: string, port: number): MySQLInfo | null {
        return null;
    }
    

    /**
    * ConnectWithDSN connects to MySQL database using given DSN.
    * we override mysql dialer with fastdialer so it respects network policy
    * If connection is successful, it returns true.
    * @example
    * ```javascript
    * const mysql = require('nuclei/mysql');
    * const client = new mysql.MySQLClient;
    * const connected = client.ConnectWithDSN('username:password@tcp(acme.com:3306)/');
    * ```
    */
    public ConnectWithDSN(dsn: string): boolean | null {
        return null;
    }
    

    /**
    * ExecuteQueryWithOpts connects to Mysql database using given credentials
    * and executes a query on the db.
    * @example
    * ```javascript
    * const mysql = require('nuclei/mysql');
    * const options = new mysql.MySQLOptions();
    * options.Host = 'acme.com';
    * options.Port = 3306;
    * const result = mysql.ExecuteQueryWithOpts(options, 'SELECT * FROM users');
    * log(to_json(result));
    * ```
    */
    public ExecuteQueryWithOpts(opts: MySQLOptions, query: string): SQLResult | null | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to Mysql database using given credentials
    * and executes a query on the db.
    * @example
    * ```javascript
    * const mysql = require('nuclei/mysql');
    * const result = mysql.ExecuteQuery('acme.com', 3306, 'username', 'password', 'SELECT * FROM users');
    * log(to_json(result));
    * ```
    */
    public ExecuteQuery(host: string, port: number, username: string): SQLResult | null | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to Mysql database using given credentials
    * and executes a query on the db.
    * @example
    * ```javascript
    * const mysql = require('nuclei/mysql');
    * const result = mysql.ExecuteQueryOnDB('acme.com', 3306, 'username', 'password', 'dbname', 'SELECT * FROM users');
    * log(to_json(result));
    * ```
    */
    public ExecuteQueryOnDB(host: string, port: number, username: string): SQLResult | null | null {
        return null;
    }
    

}



/**
 * MySQLInfo contains information about MySQL server.
 * this is returned when fingerprint is successful
 */
export interface MySQLInfo {
    
    Host?: string,
    
    IP?: string,
    
    Port?: number,
    
    Protocol?: string,
    
    TLS?: boolean,
    
    Transport?: string,
    
    Version?: string,
    
    Debug?: ServiceMySQL,
    
    Raw?: string,
}



/**
 * MySQLOptions defines the data source name (DSN) options required to connect to a MySQL database.
 * along with other options like Timeout etc
 * @example
 * ```javascript
 * const mysql = require('nuclei/mysql');
 * const options = new mysql.MySQLOptions();
 * options.Host = 'acme.com';
 * options.Port = 3306;
 * ```
 */
export interface MySQLOptions {
    
    Host?: string,
    
    Port?: number,
    
    Protocol?: string,
    
    Username?: string,
    
    Password?: string,
    
    DbName?: string,
    
    RawQuery?: string,
    
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
 * ServiceMySQL Interface
 */
export interface ServiceMySQL {
    
    PacketType?: string,
    
    ErrorMessage?: string,
    
    ErrorCode?: number,
}

