

/**
 * Connect tries to connect redis server with password
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const connected = redis.Connect('acme.com', 6379, 'password');
 * ```
 */
export function Connect(host: string, port: number, password: string): boolean | null {
    return null;
}



/**
 * GetServerInfo returns the server info for a redis server
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const info = redis.GetServerInfo('acme.com', 6379);
 * ```
 */
export function GetServerInfo(host: string, port: number): string | null {
    return null;
}



/**
 * GetServerInfoAuth returns the server info for a redis server
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const info = redis.GetServerInfoAuth('acme.com', 6379, 'password');
 * ```
 */
export function GetServerInfoAuth(host: string, port: number, password: string): string | null {
    return null;
}



/**
 * IsAuthenticated checks if the redis server requires authentication
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const isAuthenticated = redis.IsAuthenticated('acme.com', 6379);
 * ```
 */
export function IsAuthenticated(host: string, port: number): boolean | null {
    return null;
}



/**
 * RunLuaScript runs a lua script on the redis server
 * @example
 * ```javascript
 * const redis = require('nuclei/redis');
 * const result = redis.RunLuaScript('acme.com', 6379, 'password', 'return redis.call("get", KEYS[1])');
 * ```
 */
export function RunLuaScript(host: string, port: number, password: string, script: string): any | null {
    return null;
}

