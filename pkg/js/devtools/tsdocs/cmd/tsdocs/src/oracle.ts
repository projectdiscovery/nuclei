
/**
 * OracleClient Class
 */
export class OracleClient {
    

    /**
    * IsOracle checks if a host is running an Oracle server.
    * @throws {Error} - if the operation fails
    */
    public IsOracle(host: string, port: number): IsOracleResponse | null {
        return null;
    }
    

}


/**
 * IsOracleResponse interface
 */
export interface IsOracleResponse {
    
    IsOracle?: boolean,
    
    Banner?: string,
}

