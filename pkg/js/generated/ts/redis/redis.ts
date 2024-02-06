

/**
 * Connect tries to connect redis server with password
* @throws {Error} - if the operation fails
 */
export function Connect(host: string, port: number, password: string): boolean | null {
    return null;
}



/**
 * GetServerInfo returns the server info for a redis server
* @throws {Error} - if the operation fails
 */
export function GetServerInfo(host: string, port: number): string | null {
    return null;
}



/**
 * GetServerInfoAuth returns the server info for a redis server
* @throws {Error} - if the operation fails
 */
export function GetServerInfoAuth(host: string, port: number, password: string): string | null {
    return null;
}



/**
 * IsAuthenticated checks if the redis server requires authentication
* @throws {Error} - if the operation fails
 */
export function IsAuthenticated(host: string, port: number): boolean | null {
    return null;
}



/**
 * RunLuaScript runs a lua script on
* @throws {Error} - if the operation fails
 */
export function RunLuaScript(host: string, port: number, password: string, script: string): any | null {
    return null;
}

