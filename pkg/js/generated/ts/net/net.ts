

/**
 * Open opens a new connection to the address with a timeout.
 * supported protocols: tcp, udp
* @throws {Error} - if the operation fails
 */
export function Open(protocol: string): NetConn | null {
    return null;
}



/**
 * Open opens a new connection to the address with a timeout.
 * supported protocols: tcp, udp
* @throws {Error} - if the operation fails
 */
export function OpenTLS(protocol: string): NetConn | null {
    return null;
}



/**
 * NetConn Class
 */
export class NetConn {
    

    // Constructor of NetConn
    constructor() {}
    /**
    * Close closes the connection.
    * @throws {Error} - if the operation fails
    */
    public Close(): void {
        return;
    }
    

    /**
    * SetTimeout sets read/write timeout for the connection (in seconds).
    */
    public SetTimeout(value: number): void {
        return;
    }
    

    /**
    * SendArray sends array data to connection
    * @throws {Error} - if the operation fails
    */
    public SendArray(data: any): void {
        return;
    }
    

    /**
    * SendHex sends hex data to connection
    * @throws {Error} - if the operation fails
    */
    public SendHex(data: string): void {
        return;
    }
    

    /**
    * Send sends data to the connection with a timeout.
    * @throws {Error} - if the operation fails
    */
    public Send(data: string): void {
        return;
    }
    

    /**
    * Recv receives data from the connection with a timeout.
    * If N is 0, it will read all data sent by the server with 8MB limit.
    * @throws {Error} - if the operation fails
    */
    public Recv(N: number): Uint8Array | null {
        return null;
    }
    

    /**
    * RecvString receives data from the connection with a timeout
    * output is returned as a string.
    * If N is 0, it will read all data sent by the server with 8MB limit.
    * @throws {Error} - if the operation fails
    */
    public RecvString(N: number): string | null {
        return null;
    }
    

    /**
    * RecvHex receives data from the connection with a timeout
    * in hex format.
    * If N is 0,it will read all data sent by the server with 8MB limit.
    * @throws {Error} - if the operation fails
    */
    public RecvHex(N: number): string | null {
        return null;
    }
    

}

