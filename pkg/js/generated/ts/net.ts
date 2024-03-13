

/**
 * Open opens a new connection to the address with a timeout.
 * supported protocols: tcp, udp
 * @example
 * ```javascript
 * const net = require('nuclei/net');
 * const conn = net.Open('tcp', 'acme.com:80');
 * ```
 */
export function Open(protocol: string): NetConn | null {
    return null;
}



/**
 * Open opens a new connection to the address with a timeout.
 * supported protocols: tcp, udp
 * @example
 * ```javascript
 * const net = require('nuclei/net');
 * const conn = net.OpenTLS('tcp', 'acme.com:443');
 * ```
 */
export function OpenTLS(protocol: string): NetConn | null {
    return null;
}



/**
 * NetConn is a connection to a remote host.
 * this is returned/create by Open and OpenTLS functions.
 * @example
 * ```javascript
 * const net = require('nuclei/net');
 * const conn = net.Open('tcp', 'acme.com:80');
 * ```
 */
export class NetConn {
    

    // Constructor of NetConn
    constructor() {}
    /**
    * Close closes the connection.
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * conn.Close();
    * ```
    */
    public Close(): void {
        return;
    }
    

    /**
    * SetTimeout sets read/write timeout for the connection (in seconds).
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * conn.SetTimeout(10);
    * ```
    */
    public SetTimeout(value: number): void {
        return;
    }
    

    /**
    * SendArray sends array data to connection
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * conn.SendArray(['hello', 'world']);
    * ```
    */
    public SendArray(data: any): void {
        return;
    }
    

    /**
    * SendHex sends hex data to connection
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * conn.SendHex('68656c6c6f');
    * ```
    */
    public SendHex(data: string): void {
        return;
    }
    

    /**
    * Send sends data to the connection with a timeout.
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * conn.Send('hello');
    * ```
    */
    public Send(data: string): void {
        return;
    }
    

    /**
    * RecvFull receives data from the connection with a timeout.
    * If N is 0, it will read all data sent by the server with 8MB limit.
    * it tries to read until N bytes or timeout is reached.
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * const data = conn.RecvFull(1024);
    * ```
    */
    public RecvFull(N: number): Uint8Array | null {
        return null;
    }
    

    /**
    * Recv is similar to RecvFull but does not guarantee full read instead
    * it creates a buffer of N bytes and returns whatever is returned by the connection
    * for reading headers or initial bytes from the server this is usually used.
    * for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFull.
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * const data = conn.Recv(1024);
    * log(`Received ${data.length} bytes from the server`)
    * ```
    */
    public Recv(N: number): Uint8Array | null {
        return null;
    }
    

    /**
    * RecvFullString receives data from the connection with a timeout
    * output is returned as a string.
    * If N is 0, it will read all data sent by the server with 8MB limit.
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * const data = conn.RecvFullString(1024);
    * ```
    */
    public RecvFullString(N: number): string | null {
        return null;
    }
    

    /**
    * RecvString is similar to RecvFullString but does not guarantee full read, instead
    * it creates a buffer of N bytes and returns whatever is returned by the connection
    * for reading headers or initial bytes from the server this is usually used.
    * for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFullString.
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * const data = conn.RecvString(1024);
    * ```
    */
    public RecvString(N: number): string | null {
        return null;
    }
    

    /**
    * RecvFullHex receives data from the connection with a timeout
    * in hex format.
    * If N is 0,it will read all data sent by the server with 8MB limit.
    * until N bytes or timeout is reached.
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * const data = conn.RecvFullHex(1024);
    * ```
    */
    public RecvFullHex(N: number): string | null {
        return null;
    }
    

    /**
    * RecvHex is similar to RecvFullHex but does not guarantee full read instead
    * it creates a buffer of N bytes and returns whatever is returned by the connection
    * for reading headers or initial bytes from the server this is usually used.
    * for reading a fixed number of already known bytes (ex: body based on content-length) use RecvFull.
    * @example
    * ```javascript
    * const net = require('nuclei/net');
    * const conn = net.Open('tcp', 'acme.com:80');
    * const data = conn.RecvHex(1024);
    * ```
    */
    public RecvHex(N: number): string | null {
        return null;
    }
    

}

