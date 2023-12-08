
/**
 * IsSMTPResponse interface
 */
export interface IsSMTPResponse {
    
    IsSMTP?: boolean,
    
    Banner?: string,
}


/**
 * SMTPClient Class
 */
export class SMTPClient {
    

    /**
    * IsSMTP checks if a host is running a SMTP server.
    * @throws {Error} - if the operation fails
    */
    public IsSMTP(host: string, port: number): IsSMTPResponse | null {
        return null;
    }
    

}

