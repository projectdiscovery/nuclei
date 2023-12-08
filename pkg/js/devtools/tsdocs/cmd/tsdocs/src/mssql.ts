
/**
 * MSSQLClient Class
 */
export class MSSQLClient {
    

    /**
    * Connect connects to MS SQL database using given credentials.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @throws {Error} - if the operation fails
    */
    public Connect(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * ConnectWithDB connects to MS SQL database using given credentials and database name.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @throws {Error} - if the operation fails
    */
    public ConnectWithDB(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * IsMssql checks if the given host is running MS SQL database.
    * If the host is running MS SQL database, it returns true.
    * If the host is not running MS SQL database, it returns false.
    * @throws {Error} - if the operation fails
    */
    public IsMssql(host: string, port: number): boolean | null {
        return null;
    }
    

}

