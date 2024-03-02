

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

