

/**
 * IsTelnet checks if a host is running a Telnet server.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const isTelnet = telnet.IsTelnet('acme.com', 23);
 * log(toJSON(isTelnet));
 * ```
 */
export function IsTelnet(host: string, port: number): IsTelnetResponse | null {
    return null;
}

/**
 * TelnetClient is a client for Telnet servers.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const client = new telnet.TelnetClient();
 * ```
 */
export class TelnetClient {
    
    /**
     * Connect tries to connect to provided host and port with telnet.
     * Optionally provides username and password for authentication.
     * Returns state of connection. If the connection is successful,
     * the function will return true, otherwise false.
     * @example
     * ```javascript
     * const telnet = require('nuclei/telnet');
     * const client = new telnet.TelnetClient();
     * const connected = client.Connect('acme.com', 23, 'username', 'password');
     * ```
     */
    public Connect(host: string, port: number, username: string, password: string): boolean {
        return false;
    }

    /**
     * Info gathers information about the telnet server including encryption support.
     * Based on Nmap's telnet-encryption.nse script functionality.
     * @example
     * ```javascript
     * const telnet = require('nuclei/telnet');
     * const client = new telnet.TelnetClient();
     * const info = client.Info('acme.com', 23);
     * log(toJSON(info));
     * ```
     */
    public Info(host: string, port: number): TelnetInfoResponse | null {
        return null;
    }
}

/**
 * IsTelnetResponse is the response from the IsTelnet function.
 * this is returned by IsTelnet function.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const isTelnet = telnet.IsTelnet('acme.com', 23);
 * log(toJSON(isTelnet));
 * ```
 */
export interface IsTelnetResponse {
    
    IsTelnet?: boolean,
    
    Banner?: string,
}

/**
 * TelnetInfoResponse is the response from the Info function.
 * @example
 * ```javascript
 * const telnet = require('nuclei/telnet');
 * const client = new telnet.TelnetClient();
 * const info = client.Info('acme.com', 23);
 * log(toJSON(info));
 * ```
 */
export interface TelnetInfoResponse {
    
    SupportsEncryption?: boolean,
    
    Banner?: string,
    
    Options?: { [key: number]: number[] },
}

