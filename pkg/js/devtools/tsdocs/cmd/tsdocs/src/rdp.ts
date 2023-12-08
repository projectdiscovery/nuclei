
/**
 * CheckRDPAuthResponse interface
 */
export interface CheckRDPAuthResponse {
    
    PluginInfo?: ServiceRDP,
    
    Auth?: boolean,
}


/**
 * RDPClient Class
 */
export class RDPClient {
    

    /**
    * IsRDP checks if the given host and port are running rdp server.
    * If connection is successful, it returns true.
    * If connection is unsuccessful, it returns false and error.
    * The Name of the OS is also returned if the connection is successful.
    * @throws {Error} - if the operation fails
    */
    public IsRDP(host: string, port: number): IsRDPResponse | null {
        return null;
    }
    

    /**
    * CheckRDPAuth checks if the given host and port are running rdp server
    * with authentication and returns their metadata.
    * @throws {Error} - if the operation fails
    */
    public CheckRDPAuth(host: string, port: number): CheckRDPAuthResponse | null {
        return null;
    }
    

}


/**
 * IsRDPResponse interface
 */
export interface IsRDPResponse {
    
    IsRDP?: boolean,
    
    OS?: string,
}


/**
 * ServiceRDP Interface
 */
export interface ServiceRDP {
    
    TargetName?: string,
    
    NetBIOSComputerName?: string,
    
    NetBIOSDomainName?: string,
    
    DNSComputerName?: string,
    
    DNSDomainName?: string,
    
    ForestName?: string,
    
    OSFingerprint?: string,
    
    OSVersion?: string,
}

