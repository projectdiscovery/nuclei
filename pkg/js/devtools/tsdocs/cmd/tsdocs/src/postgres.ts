
/**
 * PGClient Class
 */
export class PGClient {
    

    /**
    * IsPostgres checks if the given host and port are running Postgres database.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * @throws {Error} - if the operation fails
    */
    public IsPostgres(host: string, port: number): boolean | null {
        return null;
    }
    

    /**
    * Connect connects to Postgres database using given credentials.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @throws {Error} - if the operation fails
    */
    public Connect(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

    /**
    * ExecuteQuery connects to Postgres database using given credentials and database name.
    * and executes a query on the db.
    * @throws {Error} - if the operation fails
    */
    public ExecuteQuery(host: string, port: number, username: string): string | null {
        return null;
    }
    

    /**
    * ConnectWithDB connects to Postgres database using given credentials and database name.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The connection is closed after the function returns.
    * @throws {Error} - if the operation fails
    */
    public ConnectWithDB(host: string, port: number, username: string): boolean | null {
        return null;
    }
    

}

