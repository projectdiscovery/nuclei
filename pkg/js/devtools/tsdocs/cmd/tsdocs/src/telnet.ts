
/**
 * IsTelnetResponse interface
 */
export interface IsTelnetResponse {
    
    IsTelnet?: boolean,
    
    Banner?: string,
}


/**
 * TelnetClient Class
 */
export class TelnetClient {
    

    /**
    * IsTelnet checks if a host is running a Telnet server.
    * @throws {Error} - if the operation fails
    */
    public IsTelnet(host: string, port: number): IsTelnetResponse | null {
        return null;
    }
    

}

