
/**
 * MySQLClient Class
 */
export class MySQLClient {
    

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
    * IsMySQL checks if the given host is running MySQL database.
    * If the host is running MySQL database, it returns true.
    * If the host is not running MySQL database, it returns false.
    * @throws {Error} - if the operation fails
    */
    public IsMySQL(host: string, port: number): boolean | null {
        return null;
    }
    

    /**
    * ConnectWithDB connects to MySQL database using given credentials and database name.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @throws {Error} - if the operation fails
    */
    public ConnectWithDB(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to Mysql database using given credentials and database name.
    * and executes a query on the db.
    * @throws {Error} - if the operation fails
    */
    public ExecuteQuery(host: string, port: number, username: string): string | null {
        return null;
    }
    

}

