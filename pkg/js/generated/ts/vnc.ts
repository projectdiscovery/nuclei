

/**
 * IsVNC checks if a host is running a VNC server.
 * It returns a boolean indicating if the host is running a VNC server
 * and the banner of the VNC server.
 * @example
 * ```javascript
 * const vnc = require('nuclei/vnc');
 * const isVNC = vnc.IsVNC('acme.com', 5900);
 * log(toJSON(isVNC));
 * ```
 */
export function IsVNC(host: string, port: number): IsVNCResponse | null {
    return null;
}



/**
 * IsVNCResponse is the response from the IsVNC function.
 * @example
 * ```javascript
 * const vnc = require('nuclei/vnc');
 * const isVNC = vnc.IsVNC('acme.com', 5900);
 * log(toJSON(isVNC));
 * ```
 */
export interface IsVNCResponse {
    
    IsVNC?: boolean,
    
    Banner?: string,
}

