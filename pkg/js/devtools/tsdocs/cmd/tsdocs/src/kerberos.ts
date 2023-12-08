
/**
 * KerberosClient Class
 */
export class KerberosClient {
    

    /**
    * EnumerateUser returns true if the user exists in the domain
    * If the user is not found, false is returned.
    * If the user is found, true is returned. Optionally, the AS-REP
    * hash is also returned if discovered.
    * @throws {Error} - if the operation fails
    */
    public EnumerateUser(domain: string, username: string): EnumerateUserResponse | null {
        return null;
    }
    

}


/**
 * EnumerateUserResponse interface
 */
export interface EnumerateUserResponse {
    
    Valid?: boolean,
    
    ASREPHash?: string,
}

