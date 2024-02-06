

/**
 * BuildDSN builds a MySQL data source name (DSN) from the given options.
* @throws {Error} - if the operation fails
 */
export function BuildDSN(opts: MySQLOptions): string | null {
    return null;
}



/**
 * MySQLClient Class
 */
export class MySQLClient {
    

    // Constructor of MySQLClient
    constructor() {}
    /**
    * IsMySQL checks if the given host is running MySQL database.
    * If the host is running MySQL database, it returns true.
    * If the host is not running MySQL database, it returns false.
    * @throws {Error} - if the operation fails
    */
    public IsMySQL(host: string, port: number): boolean | null {
        return null;
    }
    

    /**
    * Connect connects to MySQL database using given credentials.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @throws {Error} - if the operation fails
    */
    public Connect(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * returns MySQLInfo when fingerpint is successful
    * @throws {Error} - if the operation fails
    */
    public FingerprintMySQL(host: string, port: number): MySQLInfo | null {
        return null;
    }
    

    /**
    * ConnectWithDSN connects to MySQL database using given DSN.
    * we override mysql dialer with fastdialer so it respects network policy
    * @throws {Error} - if the operation fails
    */
    public ConnectWithDSN(dsn: string): boolean | null {
        return null;
    }
    

    /**
    * ExecuteQueryWithOpts Method
    * @throws {Error} - if the operation fails
    */
    public ExecuteQueryWithOpts(opts: MySQLOptions, query: string): SQLResult | null | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to Mysql database using given credentials
    * and executes a query on the db.
    * @throws {Error} - if the operation fails
    */
    public ExecuteQuery(host: string, port: number, username: string): SQLResult | null | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to Mysql database using given credentials
    * and executes a query on the db.
    * @throws {Error} - if the operation fails
    */
    public ExecuteQueryOnDB(host: string, port: number, username: string): SQLResult | null | null {
        return null;
    }
    

}



/**
 * MySQLInfo interface
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
 * MySQLOptions interface
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

