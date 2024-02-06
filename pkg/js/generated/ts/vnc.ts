

/**
 * VNCClient Class
 */
export class VNCClient {
    

    // Constructor of VNCClient
    constructor() {}
    /**
    * IsVNC checks if a host is running a VNC server.
    * It returns a boolean indicating if the host is running a VNC server
    * and the banner of the VNC server.
    * @throws {Error} - if the operation fails
    */
    public IsVNC(host: string, port: number): IsVNCResponse | null {
        return null;
    }
    

}



/**
 * IsVNCResponse interface
 */
export interface IsVNCResponse {
    
    IsVNC?: boolean,
    
    Banner?: string,
}

